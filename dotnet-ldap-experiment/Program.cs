using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
using NuGet.Versioning;

var ldapHost = Environment.GetEnvironmentVariable("LDAP_HOST") ?? throw new ArgumentException("The LDAP_HOST environment variable must be set.");
var ldapBase = Environment.GetEnvironmentVariable("LDAP_BASE");
var ldapFilter = Environment.GetEnvironmentVariable("LDAP_FILTER") ?? "(&(objectCategory=person)(objectClass=user)(c=ZZ))";

using var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(ldapHost), credential: null, AuthType.Kerberos);
ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
var assembly = typeof(LdapConnection).Assembly;
var version = SemanticVersion.Parse(assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? throw new InvalidDataException("Informational version is missing"));
if (version.Major < 10)
{
    // The fix is available since v10.0.0-preview.1.25080.5, see https://github.com/dotnet/runtime/pull/109450 and https://github.com/dotnet/runtime/commit/9970e70bb49f4e089a17dcea92882c21834ff4b1
    // So explicitly setting the protocol version is only needed when using an earlier version
    Console.WriteLine($"Enabling ProtocolVersion 3 for {assembly.GetName().Name} version {version}");
    ldapConnection.SessionOptions.ProtocolVersion = 3;
}

try
{
    var searchRequest = new SearchRequest(ldapBase, ldapFilter, SearchScope.Subtree, "distinguishedName");
    var response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
    foreach (SearchResultEntry entry in response.Entries)
    {
        Console.WriteLine(entry.Attributes["distinguishedName"]?.GetValues(typeof(string))?.OfType<string>().FirstOrDefault());
    }
    Console.WriteLine($"Found {response.Entries.Count} entries");

    return 0;
}
catch (LdapException ldapException)
{
    Console.Error.WriteLine(ldapException.ServerErrorMessage);
    Console.Error.WriteLine(ldapException);

    return 1;
}