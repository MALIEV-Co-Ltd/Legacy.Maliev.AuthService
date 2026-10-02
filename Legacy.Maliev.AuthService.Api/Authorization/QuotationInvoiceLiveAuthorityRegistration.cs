using Legacy.Maliev.AuthService.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Registers only the new scoped quotation authority boundary.</summary>
public static class QuotationInvoiceLiveAuthorityRegistration
{
    /// <summary>Registers only scoped live transport, without changing general permission policy.</summary>
    public static IHostApplicationBuilder AddQuotationInvoiceLiveAuthority(this IHostApplicationBuilder builder)
    {
        builder.AddLegacyAuthServiceTokenExchange();
        var services = builder.Services;
        services.AddScoped<IQuotationInvoiceLiveAuthorityClient, QuotationInvoiceLiveAuthorityClient>();
        services.AddTransient<BoundedQuotationWorkloadExchangeHandler>();
#pragma warning disable EXTEXP0001 // Intentional client-local isolation from inherited resilience; no shared policy changes.
        services.AddHttpClient(LegacyServiceAccessTokenProvider.HttpClientName)
            .RemoveAllResilienceHandlers()
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false })
            .AddHttpMessageHandler<BoundedQuotationWorkloadExchangeHandler>()
            .RedactLoggedHeaders(["Authorization", "X-Maliev-IAM-Live-Check-Key"]);
        services.AddHttpClient(QuotationInvoiceLiveAuthorityClient.HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(10))
            .RemoveAllResilienceHandlers()
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false })
            .RedactLoggedHeaders(["Authorization", "X-Maliev-IAM-Live-Check-Key"]);
#pragma warning restore EXTEXP0001
        return builder;
    }
}
