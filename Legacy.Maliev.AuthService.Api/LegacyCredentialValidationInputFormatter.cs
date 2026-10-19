using System.Text;
using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Mvc.Formatters;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Legacy.Maliev.AuthService.Api;

/// <summary>Retains the original Newtonsoft input grammar only for the two compatibility actions.</summary>
public sealed class LegacyCredentialValidationInputFormatter : TextInputFormatter
{
    private static readonly JsonSerializerSettings SourceSettings = new()
    {
        ContractResolver = new DefaultContractResolver { NamingStrategy = new CamelCaseNamingStrategy() },
        MissingMemberHandling = MissingMemberHandling.Ignore,
        MaxDepth = 32,
        TypeNameHandling = TypeNameHandling.None,
        NullValueHandling = NullValueHandling.Ignore,
        ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
    };

    /// <summary>Uses the original MVC JSON media types and supported encodings.</summary>
    public LegacyCredentialValidationInputFormatter()
    {
        SupportedMediaTypes.Add("application/json");
        SupportedMediaTypes.Add("text/json");
        SupportedMediaTypes.Add("application/*+json");
        SupportedEncodings.Add(UTF8EncodingWithoutBOM);
        SupportedEncodings.Add(UTF16EncodingLittleEndian);
    }

    /// <inheritdoc />
    protected override bool CanReadType(Type type) => type == typeof(LegacyCredentialValidationRequest);

    /// <inheritdoc />
    public override async Task<InputFormatterResult> ReadRequestBodyAsync(InputFormatterContext context, Encoding encoding)
    {
        // Read asynchronously into memory only; never spill submitted credentials to a temporary file.
        using var requestReader = context.ReaderFactory(context.HttpContext.Request.Body, encoding);
        var body = new StringBuilder();
        var buffer = new char[1024];
        while (true)
        {
            context.HttpContext.RequestAborted.ThrowIfCancellationRequested();
            var read = await requestReader.ReadAsync(buffer.AsMemory(), context.HttpContext.RequestAborted);
            context.HttpContext.RequestAborted.ThrowIfCancellationRequested();
            if (read == 0) break;
            body.Append(buffer, 0, read);
        }
        using var text = new StringReader(body.ToString());
        using var json = new JsonTextReader(text);
        try
        {
            var serializer = JsonSerializer.Create(SourceSettings);
            // Original MVC settings leave CheckAdditionalContent false; do not add a trailing-content rejection.
            var model = serializer.Deserialize<LegacyCredentialValidationRequest>(json);
            return model is null && !context.TreatEmptyInputAsDefaultValue
                ? InputFormatterResult.NoValue()
                : InputFormatterResult.Success(model);
        }
        catch (Exception exception) when (exception is JsonException or OverflowException or FormatException)
        {
            // Json.NET errors can contain submitted credentials; retain only a fixed safe model-state error.
            context.ModelState.TryAddModelError(context.ModelName, "Invalid credential JSON.");
            return InputFormatterResult.Failure();
        }
    }
}
