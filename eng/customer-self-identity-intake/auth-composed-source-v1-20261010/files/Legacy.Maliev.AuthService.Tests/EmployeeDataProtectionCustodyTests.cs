using System.Xml.Linq;
using Legacy.Maliev.AuthService.Infrastructure;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class EmployeeDataProtectionCustodyTests
{
    [Theory]
    [InlineData("<key><descriptor><masterKey>synthetic-plaintext</masterKey></descriptor></key>")]
    [InlineData("<key><descriptor /></key>")]
    [InlineData("<unexpected />")]
    public void StoreElement_UnprotectedOrUnknownMaterialIsRejectedBeforeDatabaseAccess(string xml)
    {
        var repository = new EmployeeDataProtectionXmlRepository("invalid-connection-never-opened");
        var exception = Assert.Throws<InvalidOperationException>(() => repository.StoreElement(XElement.Parse(xml), "synthetic"));
        Assert.DoesNotContain("synthetic-plaintext", exception.Message, StringComparison.Ordinal);
    }
}
