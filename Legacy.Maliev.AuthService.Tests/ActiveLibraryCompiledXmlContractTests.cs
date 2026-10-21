using System.Xml.Linq;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Protects compiled library XML and the test project's source-artifact boundary.</summary>
public sealed class ActiveLibraryCompiledXmlContractTests
{
    /// <summary>Requires each library's emitted XML manifest and a documented member in that assembly.</summary>
    /// <param name="assemblyName">The active library whose compiled XML must accompany its assembly.</param>
    /// <param name="memberName">The compiler documentation identifier of a representative public member.</param>
    [Theory]
    [InlineData("Legacy.Maliev.AuthService.Application", "M:Legacy.Maliev.AuthService.Application.AuthenticationResult.Failed")]
    [InlineData("Legacy.Maliev.AuthService.Application", "T:Legacy.Maliev.AuthService.Application.LegacyCredentialValidationRequest")]
    [InlineData("Legacy.Maliev.AuthService.Application", "P:Legacy.Maliev.AuthService.Application.LegacyCredentialValidationRequest.Username")]
    [InlineData("Legacy.Maliev.AuthService.Application", "P:Legacy.Maliev.AuthService.Application.LegacyCredentialValidationRequest.Password")]
    [InlineData("Legacy.Maliev.AuthService.Domain", "P:Legacy.Maliev.AuthService.Domain.IdentityActionToken.RecoveryVersion")]
    [InlineData("Legacy.Maliev.AuthService.Infrastructure", "P:Legacy.Maliev.AuthService.Infrastructure.EmployeeRecoveryEffect.ActionId")]
    public void ActiveLibrary_EmitsCompiledXmlWithDocumentedMember(string assemblyName, string memberName)
    {
        var documentPath = Path.Combine(AppContext.BaseDirectory, assemblyName + ".xml");
        Assert.True(File.Exists(documentPath), $"Compiled XML documentation is missing: {documentPath}");

        var document = XDocument.Load(documentPath);
        Assert.Equal(assemblyName, document.Root?.Element("assembly")?.Element("name")?.Value);
        var member = Assert.Single(document.Root?.Element("members")?.Elements("member")
            .Where(element => element.Attribute("name")?.Value == memberName) ?? []);
        Assert.False(string.IsNullOrWhiteSpace(member.Element("summary")?.Value),
            $"Compiled XML summary is missing for {memberName}.");
    }

    /// <summary>Keeps the nonpackable test project's compiler artifacts out of source and stale copy items.</summary>
    [Fact]
    public void TestProject_IsNonpackableAndKeepsGeneratedXmlOutOfSource()
    {
        const string assemblyName = "Legacy.Maliev.AuthService.Tests";
        var projectDirectory = Path.Combine(FindRepositoryRoot(), assemblyName);
        var project = XDocument.Load(Path.Combine(projectDirectory, assemblyName + ".csproj"));

        Assert.Equal("false", Assert.Single(project.Descendants("IsPackable")).Value.Trim(), ignoreCase: true);
        Assert.Empty(project.Descendants("DocumentationFile"));
        Assert.DoesNotContain(project.Descendants("None"), element =>
            ((string?)element.Attribute("Update"))?.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) == true);
        Assert.False(File.Exists(Path.Combine(projectDirectory, assemblyName + ".xml")));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
