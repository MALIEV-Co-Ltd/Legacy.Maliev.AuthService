using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Npgsql;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Retains encrypted employee key-ring elements in PostgreSQL without runtime schema or key creation.</summary>
public sealed class EmployeeDataProtectionXmlRepository(string connectionString) : IXmlRepository
{
    /// <inheritdoc />
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false, Timeout = 10 }.ConnectionString);
        connection.Open();
        using var command = new NpgsqlCommand("SELECT \"Xml\" FROM \"DataProtectionKeys\" ORDER BY \"Id\"", connection);
        command.CommandTimeout = 10;
        using var reader = command.ExecuteReader();
        var elements = new List<XElement>();
        while (reader.Read())
        {
            // Original EF repository ignores nullable/empty Xml placeholders.
            if (reader.IsDBNull(0) || string.IsNullOrEmpty(reader.GetString(0))) continue;
            using var text = new StringReader(reader.GetString(0));
            using var xml = XmlReader.Create(text, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            var element = XElement.Load(xml);
            EnsureProtected(element);
            elements.Add(element);
        }
        if (!elements.Any(element => element.Name.LocalName == "key"))
            throw new InvalidOperationException("The adopted protected employee key ring is unavailable.");
        return elements;
    }

    /// <inheritdoc />
    public void StoreElement(XElement element, string friendlyName)
    {
        EnsureProtected(element);
        using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false, Timeout = 10 }.ConnectionString);
        connection.Open();
        using var command = new NpgsqlCommand("INSERT INTO \"DataProtectionKeys\" (\"FriendlyName\", \"Xml\") VALUES (@name, @xml)", connection);
        command.CommandTimeout = 10;
        command.Parameters.AddWithValue("name", friendlyName);
        command.Parameters.AddWithValue("xml", element.ToString(SaveOptions.DisableFormatting));
        command.ExecuteNonQuery();
    }

    private static void EnsureProtected(XElement element)
    {
        ArgumentNullException.ThrowIfNull(element);
        if (element.DescendantsAndSelf().Any(node => node.Name.LocalName == "masterKey") ||
            (element.Name.LocalName == "key" && !element.Descendants().Any(node => node.Name.LocalName == "encryptedSecret")))
            throw new InvalidOperationException("Unprotected employee Data Protection key material is not permitted.");
        if (element.Name.LocalName is not ("key" or "revocation"))
            throw new InvalidOperationException("The employee key-ring element is invalid.");
    }
}
