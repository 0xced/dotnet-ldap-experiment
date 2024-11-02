using System;
using System.DirectoryServices.Protocols;
using System.Linq;

var ldapHost = Environment.GetEnvironmentVariable("LDAP_HOST") ?? throw new ArgumentException("The LDAP_HOST environment variable must be set.");
var ldapBase = Environment.GetEnvironmentVariable("LDAP_BASE") ?? string.Join(',', ldapHost.Split('.').TakeLast(2).Select(e => $"DC={e}"));
var ldapFilter = Environment.GetEnvironmentVariable("LDAP_FILTER") ?? "(&(objectCategory=person)(objectClass=user)(c=ZZ))";

using var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(ldapHost), credential: null, AuthType.Kerberos);
ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
var searchRequest = new SearchRequest(ldapBase, ldapFilter, SearchScope.Subtree, "distinguishedName");
var response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
foreach (SearchResultEntry entry in response.Entries)
{
    Console.WriteLine(entry.Attributes["distinguishedName"]?.GetValues(typeof(string))?.OfType<string>().FirstOrDefault());
}
Console.WriteLine($"Found {response.Entries.Count} entries");