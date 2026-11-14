using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
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
    /// <summary>
    /// Searches the LDAP directory.
    /// </summary>
    /// <param name="searchBase">The distinguished name where to start searching.</param>
    /// <param name="filter">The LDAP filter, see https://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm for the syntax.</param>
    /// <param name="attributes">The attributes to fetch.</param>
    /// <param name="searchScope">The <see cref="SearchScope"/> to use. Default to <see cref="SearchScope.Subtree"/>.</param>
    /// <param name="pageSize">The page size. Defaults to 500 to prevent size limit issues. Ignored if less than or equal to zero.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to cancel the operation.</param>
    /// <returns>A collection of <see cref="SearchResultEntry"/> ojbects that match the specified <paramref name="filter"/>.</returns>
    public async IAsyncEnumerable<SearchResultEntry> SearchAsync(
        string searchBase,
        string filter,
        string[] attributes,
        SearchScope searchScope = SearchScope.Subtree,
        int pageSize = 500,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {

        {
            PageResultRequestControl? pageRequestControl = null;
            var request = new SearchRequest(searchBase, filter, searchScope, attributes);
            if (pageSize > 0)
            {
                // Perform a paged search to avoid "The size limit was exceeded"
                // See https://stackoverflow.com/questions/13567685/ldapconnection-searchrequest-throws-exception-for-the-size-limit-was-exceeded/24744365#24744365
                pageRequestControl = new PageResultRequestControl(pageSize);
                request.Controls.Add(pageRequestControl);
            }

            while (true)
            {
                var response = await _connection.SearchAsync(request, cancellationToken);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    yield return entry;
                }

                var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                if (pageRequestControl == null || cookie?.Length == 0)
                {
                    break;
                }

                pageRequestControl.Cookie = cookie;
            }
        }
    }
}