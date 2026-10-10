using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Prepares original remembered-client verification over the protected employee-owned PostgreSQL ring.</summary>
public static class EmployeeRememberedClientDataProtection
{
    /// <summary>Registers verification only, with no default-scheme change or remembered ticket issuance.</summary>
    public static void AddEmployeeRememberedClientVerification(this IHostApplicationBuilder builder)
    {
        builder.Services.AddSingleton(_ => new NamedCookieProvider(builder.Configuration));
        builder.Services.AddAuthentication().AddCookie(IdentityConstants.TwoFactorRememberMeScheme, options =>
        {
            options.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme;
            options.ExpireTimeSpan = TimeSpan.FromDays(14);
            options.SlidingExpiration = true;
            options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
            // The issuance policy has the current locked employee row. Renewal is allowed
            // there only after its subject/stamp check, avoiding a second pooled DB read.
            options.Events.OnCheckSlidingExpiration = context =>
            {
                context.ShouldRenew = false;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddOptions<CookieAuthenticationOptions>(IdentityConstants.TwoFactorRememberMeScheme)
            .Configure<NamedCookieProvider>((options, provider) => options.DataProtectionProvider = provider);
    }

    private static IDataProtectionProvider CreateProvider(IConfiguration configuration)
    {
        var discriminator = Required(configuration, "EmployeeRememberedClient:OriginalApplicationDiscriminator");
        var connection = configuration.GetConnectionString("employee-data-protection")
            ?? throw new InvalidOperationException("The employee-owned PostgreSQL Data Protection store is required.");
        var certificatePath = Required(configuration, "EmployeeRememberedClient:CertificatePath");
        var certificatePassword = Required(configuration, "EmployeeRememberedClient:CertificatePassword");
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, certificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        ServiceProvider? services = null;
        try
        {
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("The employee Data Protection custody certificate requires a private key.");
            var registrations = new ServiceCollection();
            registrations.AddLogging();
            registrations.AddDataProtection().SetApplicationName(discriminator)
                .ProtectKeysWithCertificate(certificate).DisableAutomaticKeyGeneration();
            registrations.Configure<KeyManagementOptions>(options =>
                options.XmlRepository = new EmployeeDataProtectionXmlRepository(connection));
            services = registrations.BuildServiceProvider();
            return new OwnedProvider(services.GetRequiredService<IDataProtectionProvider>(), services, certificate);
        }
        catch
        {
            services?.Dispose();
            certificate.Dispose();
            throw;
        }
    }

    private static string Required(IConfiguration configuration, string key) =>
        !string.IsNullOrWhiteSpace(configuration[key]) ? configuration[key]!
            : throw new InvalidOperationException($"Configuration '{key}' is required for original remembered-client verification.");

    private sealed class NamedCookieProvider(IConfiguration configuration) : IDataProtectionProvider, IDisposable
    {
        private readonly Lazy<IDataProtectionProvider> provider = new(() => CreateProvider(configuration));
        public IDataProtector CreateProtector(string purpose) => new DeferredProtector(provider, [purpose]);
        public void Dispose()
        {
            if (provider.IsValueCreated && provider.Value is IDisposable owned) owned.Dispose();
        }
    }

    private sealed class DeferredProtector(Lazy<IDataProtectionProvider> provider, string[] purposes) : IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => new DeferredProtector(provider, [.. purposes, purpose]);
        public byte[] Protect(byte[] plaintext) => Resolve().Protect(plaintext);
        public byte[] Unprotect(byte[] protectedData) => Resolve().Unprotect(protectedData);
        private IDataProtector Resolve()
        {
            var protector = provider.Value.CreateProtector(purposes[0]);
            foreach (var purpose in purposes.Skip(1)) protector = protector.CreateProtector(purpose);
            return protector;
        }
    }

    private sealed class OwnedProvider(IDataProtectionProvider provider, ServiceProvider services, X509Certificate2 certificate)
        : IDataProtectionProvider, IDisposable
    {
        public IDataProtector CreateProtector(string purpose) => provider.CreateProtector(purpose);
        public void Dispose()
        {
            try { services.Dispose(); }
            finally { certificate.Dispose(); }
        }
    }
}
