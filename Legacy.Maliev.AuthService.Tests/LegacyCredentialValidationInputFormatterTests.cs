using System.Text;
using Legacy.Maliev.AuthService.Api;
using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises the compatibility credential JSON formatter's grammar, selection, redaction, and cancellation contracts.
/// </summary>
public sealed class LegacyCredentialValidationInputFormatterTests
{
    /// <summary>
    /// Checks source-compatible JSON grammar and scalar lexemes across supported media types and encodings.
    /// </summary>
    /// <param name="json">The request JSON supplied to the boundary under test.</param>
    /// <param name="username">The literal username expected from the compatibility JSON.</param>
    /// <param name="password">The literal password expected from the compatibility JSON.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("{'Username':'source-user','Password':'source-password'}", "source-user", "source-password")]
    [InlineData("{/*source*/Username:'source-user',Password:'source-password',}", "source-user", "source-password")]
    [InlineData("{Username:0x10,Password:NaN}", "0x10", "NaN")]
    [InlineData("{Username:Infinity,Password:-Infinity}", "Infinity", "-Infinity")]
    [InlineData("{'Username':'source-user','Password':'correct','Password':null}", "source-user", "correct")]
    [InlineData("{'Username':'source-user','Password':'source-password'} {'ignored':true}", "source-user", "source-password")]
    [InlineData("{Username:123,Password:12345}", "123", "12345")]
    [InlineData("{Username:true,Password:false}", "true", "false")]
    [InlineData("{Username:-1.25e+2,Password:1e-2}", "-1.25e+2", "1e-2")]
    public async Task ReadAsync_SourceGrammarAndScalarLexemes_RetainsLiteralValues(
        string json, string username, string password)
    {
        using var cancellation = new CancellationTokenSource();
        foreach (var (contentType, encoding) in new[]
        {
            ("application/json; charset=utf-8", Encoding.UTF8),
            ("text/json; charset=utf-16", Encoding.Unicode),
            ("application/vnd.legacy-validation+json; charset=utf-8", Encoding.UTF8),
        })
        {
            var (result, modelState) = await ReadAsync(json, contentType, encoding, cancellation.Token);
            Assert.False(result.HasError);
            Assert.True(result.IsModelSet);
            Assert.True(modelState.IsValid);
            var model = Assert.IsType<LegacyCredentialValidationRequest>(result.Model);
            Assert.Equal(username, model.Username);
            Assert.Equal(password, model.Password);
        }
    }

    /// <summary>
    /// Checks empty-input distinctions and redacted model-state errors without exposing credential sentinels.
    /// </summary>
    /// <param name="json">The request JSON supplied to the boundary under test.</param>
    /// <param name="hasError">Whether the formatter should report a redacted input error.</param>
    /// <param name="isModelSet">Whether the formatter should produce a compatibility request model.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("", false, false)]
    [InlineData("null", false, false)]
    [InlineData(" \t", false, false)]
    [InlineData("{}", false, true)]
    [InlineData("['private-password-sentinel']", true, false)]
    [InlineData("{'Username':'private-username-sentinel','Password':['private-password-sentinel']}", true, false)]
    [InlineData("{'Username':{'private-username-sentinel':true},'Password':'private-password-sentinel'}", true, false)]
    [InlineData("{'Username':'private-username-sentinel','Password':'private-password-sentinel", true, false)]
    public async Task ReadAsync_EmptyOrMalformedInput_DistinguishesNoValueAndRedactsErrors(
        string json, bool hasError, bool isModelSet)
    {
        using var cancellation = new CancellationTokenSource();
        var (result, modelState) = await ReadAsync(
            json, "application/json", Encoding.UTF8, cancellation.Token);
        Assert.Equal(hasError, result.HasError);
        Assert.Equal(isModelSet, result.IsModelSet);
        if (hasError)
        {
            var error = Assert.Single(Assert.Single(modelState).Value!.Errors);
            Assert.Equal("Invalid credential JSON.", error.ErrorMessage);
            Assert.Null(error.Exception);
            Assert.DoesNotContain("private-username-sentinel", error.ErrorMessage, StringComparison.Ordinal);
            Assert.DoesNotContain("private-password-sentinel", error.ErrorMessage, StringComparison.Ordinal);
            Assert.Null(result.Model);
        }
        else
        {
            Assert.True(modelState.IsValid);
            if (isModelSet)
            {
                var model = Assert.IsType<LegacyCredentialValidationRequest>(result.Model);
                Assert.Null(model.Username);
                Assert.Null(model.Password);
            }
            else
            {
                Assert.Null(result.Model);
            }
        }
    }

    /// <summary>
    /// Checks selection only for the compatibility DTO and supported JSON media types.
    /// </summary>
    /// <param name="modelType">The requested model type used to select the formatter.</param>
    /// <param name="contentType">The media type submitted for formatter selection.</param>
    /// <param name="expected">Whether the formatter should accept this model type and media type.</param>
    [Theory]
    [InlineData(typeof(LegacyCredentialValidationRequest), "application/json", true)]
    [InlineData(typeof(LegacyCredentialValidationRequest), "text/json", true)]
    [InlineData(typeof(LegacyCredentialValidationRequest), "application/vnd.legacy-validation+json", true)]
    [InlineData(typeof(LoginRequest), "application/json", false)]
    [InlineData(typeof(string), "application/json", false)]
    [InlineData(typeof(LegacyCredentialValidationRequest), "text/plain", false)]
    public void CanRead_OnlyCompatibilityDtoAndJsonMediaTypes_AreSelected(
        Type modelType, string contentType, bool expected)
    {
        using var body = new MemoryStream();
        var context = CreateContext(body, contentType, modelType, CancellationToken.None);
        Assert.Equal(expected, new LegacyCredentialValidationInputFormatter().CanRead(context));
    }

    /// <summary>
    /// Checks cancellation propagation while leaving model state valid and the caller-owned request body open.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task ReadAsync_CancelledRequest_PropagatesCancellationWithoutModelStateError()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await using var body = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
        var context = CreateContext(
            body, "application/json", typeof(LegacyCredentialValidationRequest), cancellation.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new LegacyCredentialValidationInputFormatter().ReadAsync(context));
        Assert.True(context.ModelState.IsValid);
        Assert.True(body.CanRead);
    }

    private static async Task<(InputFormatterResult Result, ModelStateDictionary ModelState)> ReadAsync(
        string json, string contentType, Encoding encoding, CancellationToken cancellationToken)
    {
        await using var body = new MemoryStream(encoding.GetBytes(json));
        var context = CreateContext(
            body, contentType, typeof(LegacyCredentialValidationRequest), cancellationToken);
        var result = await new LegacyCredentialValidationInputFormatter().ReadAsync(context);
        // The formatter disposes its reader; leaveOpen keeps the request body owned by this test.
        Assert.True(body.CanRead);
        return (result, context.ModelState);
    }

    private static InputFormatterContext CreateContext(
        Stream body, string contentType, Type modelType, CancellationToken cancellationToken)
    {
        var http = new DefaultHttpContext();
        http.Request.Body = body;
        http.Request.ContentType = contentType;
        http.RequestAborted = cancellationToken;
        return new InputFormatterContext(
            http,
            string.Empty,
            new ModelStateDictionary(),
            new EmptyModelMetadataProvider().GetMetadataForType(modelType),
            (stream, encoding) => new Microsoft.AspNetCore.WebUtilities.HttpRequestStreamReader(stream, encoding));
    }
}
