using System.ComponentModel.DataAnnotations;
using Legacy.Maliev.AuthService.Application;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies request-record validation metadata is attached to constructor parameters.
/// </summary>
public sealed class RequestRecordValidationTests
{
    /// <summary>
    /// Verifies request records retain validation attributes on their primary constructor parameters.
    /// </summary>
    [Fact]
    public void RequestRecords_PlaceValidationMetadataOnPrimaryConstructorParameters()
    {
        Type[] requestTypes =
        [
            typeof(LoginRequest),
            typeof(RefreshRequest),
            typeof(RevokeRequest),
            typeof(ServiceLoginRequest),
            typeof(RegisterCustomerIdentityRequest),
            typeof(CustomerActionRequest),
            typeof(CompleteCustomerActionRequest),
            typeof(CompletePasswordResetRequest),
            typeof(ChangeCustomerEmailRequest),
            typeof(ChangeCustomerPasswordRequest),
            typeof(CreateCustomerIdentityRequest),
            typeof(UpdateCustomerIdentityRequest),
            typeof(CreateEmployeeIdentityRequest),
            typeof(UpdateEmployeeIdentityRequest),
            typeof(GoogleIdentityNonceRequest),
            typeof(GoogleExchangeRequest)
        ];

        var parameterValidationAttributes = 0;
        foreach (var requestType in requestTypes)
        {
            var constructor = Assert.Single(requestType.GetConstructors());
            foreach (var parameter in constructor.GetParameters())
            {
                parameterValidationAttributes += parameter.GetCustomAttributes(typeof(ValidationAttribute), true).Length;
            }

            Assert.All(
                requestType.GetProperties(),
                property => Assert.Empty(property.GetCustomAttributes(typeof(ValidationAttribute), true)));
        }

        Assert.True(parameterValidationAttributes > 0);
    }
}
