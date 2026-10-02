using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Buffers only the scoped legacy workload exchange before its shared provider reads the body.</summary>
public sealed class BoundedQuotationWorkloadExchangeHandler(IConfiguration configuration, IHostEnvironment environment, TimeProvider timeProvider) : DelegatingHandler
{
    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:Auth:BaseUrl"], environment, out var origin)
            || request.Method != HttpMethod.Post || request.RequestUri != new Uri(origin, "/auth/v1/service/login"))
            throw Unavailable();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        HttpResponseMessage? response = null;
        try
        {
            response = await base.SendAsync(request, linked.Token);
            var original = response.Content;
            var bytes = await QuotationAuthorityTransportBoundary.ReadBoundedAsync(original, linked.Token);
            var buffered = new ByteArrayContent(bytes);
            foreach (var header in original.Headers)
                if (!string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase))
                    buffered.Headers.TryAddWithoutValidation(header.Key, header.Value);
            response.Content = buffered;
            original.Dispose();
            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            response?.Dispose();
            throw Unavailable();
        }
        catch
        {
            response?.Dispose();
            throw;
        }
    }
    private static HttpRequestException Unavailable() => new("Scoped workload exchange is unavailable.", null, HttpStatusCode.ServiceUnavailable);
}

internal static class QuotationAuthorityTransportBoundary
{
    internal static bool TryOrigin(string? value, IHostEnvironment environment, out Uri origin)
    {
        origin = null!;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || value != value.Trim()
            || !Uri.TryCreate(value, UriKind.Absolute, out var parsed) || parsed.UserInfo.Length != 0
            || parsed.AbsolutePath != "/" || parsed.Query.Length != 0 || parsed.Fragment.Length != 0
            || parsed.Host.Length == 0 || value.Contains('\\')
            || !(parsed.Scheme == Uri.UriSchemeHttps || (environment.IsEnvironment("Testing") && parsed.Scheme == Uri.UriSchemeHttp && parsed.IsLoopback))) return false;
        if (value != parsed.GetLeftPart(UriPartial.Authority) && value != parsed.GetLeftPart(UriPartial.Authority) + "/") return false;
        origin = parsed;
        return true;
    }
    internal static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        const int maximum = 32 * 1024;
        if (content.Headers.ContentLength is > maximum) throw new HttpRequestException("Scoped response is unavailable.");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream(maximum);
        var block = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(block.AsMemory(0, (int)Math.Min(block.Length, maximum + 1 - buffer.Length)), cancellationToken);
            if (read == 0) break;
            if (buffer.Length + read > maximum) throw new HttpRequestException("Scoped response is unavailable.");
            await buffer.WriteAsync(block.AsMemory(0, read), cancellationToken);
        }
        if (content.Headers.ContentLength is long declared && declared != buffer.Length) throw new HttpRequestException("Scoped response is unavailable.");
        return buffer.ToArray();
    }
}
