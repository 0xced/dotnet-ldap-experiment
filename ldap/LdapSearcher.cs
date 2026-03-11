using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using NuGet.Versioning;

namespace ldap;

public class LdapSearcher
{
    private readonly LdapConnection _connection;

    public LdapSearcher(LdapConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));

        var assembly = typeof(LdapConnection).Assembly;
        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? throw new InvalidDataException("Informational version is missing");
        var version = SemanticVersion.Parse(informationalVersion);
        if (version.Major < 10)
        {
            // The fix for "LdapException: The feature is not supported" is available since v10.0.0-preview.1.25080.5
            // See https://github.com/dotnet/runtime/pull/109450 and https://github.com/dotnet/runtime/commit/9970e70bb49f4e089a17dcea92882c21834ff4b1
            // So explicitly setting the protocol version is only needed when using an earlier version
            connection.SessionOptions.ProtocolVersion = 3;
        }
    }

    public async IAsyncEnumerable<SearchResultEntry> SearchAsync(string? searchBase, string filter, params string[] attributes)
    {
        var request = new SearchRequest(searchBase, filter, SearchScope.Subtree, attributes);
        var response = (SearchResponse)await Task.Factory.FromAsync(_connection.BeginSendRequest, _connection.EndSendRequest, request, PartialResultProcessing.NoPartialResultSupport, state: null);

        foreach (SearchResultEntry searchResult in response.Entries)
        {
            yield return searchResult;
        }
    }
}