using System;
using System.Buffers.Binary;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using Nager.PublicSuffix;
using Nager.PublicSuffix.RuleProviders;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ldap;

[Description("Performs an LDAP search.")]
[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global", Justification = "Instantiated by Spectre.Console.Cli through reflection")]
internal class SearchCommand(IAnsiConsole console) : AsyncCommand<SearchCommand.Settings>
{
    private static readonly Encoding ValidatingUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    [SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global", Justification = "Required for Spectre.Console.Cli binding")]
    internal class Settings : CommandSettings
    {
        [Description("The LDAP filter. It should conform to the string representation for search filters as defined in RFC 4515. Example: [b](objectClass=*)[/]")]
        [CommandArgument(0, "<Filter>")]
        public string Filter { get; init; } = null!;

        [Description("The attributes to retrieve. All attributes are retrieved if not specified.")]
        [CommandArgument(1, "[Attributes]")]
        public string[] Attributes { get; init; } = [];

        [Description("Specify the host on which the ldap server is running.")]
        [CommandOption("-h <Host>")]
        public string? Host { get; init; } = null;

        [Description("Use as the starting point for the search instead of the default (derived from the LDAP server host).")]
        [CommandOption("-b <SearchBase>")]
        public string? SearchBase { get; init; } = null;

        [Description("Set the LDAP debugging level. See https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_13/contrib/ldapc%2B%2B/src/debug.h#L11-L15")]
        [CommandOption("-d <DebugLevel>")]
        public int? DebugLevel { get; init; } = null;

        [Description("Whether to canonicalize the LDAP host name for SASL authentication.")]
        [CommandOption("-c [CanonicalizeHostName]")]
        public FlagValue<bool> CanonicalizeHostName { get; init; } = null!;
    }

    protected override async Task<int> ExecuteAsync(CommandContext commandContext, Settings settings, CancellationToken cancellationToken)
    {
        try
        {
            var status = $"Searching for {settings.Filter} on {settings.Host}";

            if (settings.DebugLevel.HasValue)
            {
                LdapNative.SetDebugLevel(settings.DebugLevel.Value);

                // Don't use the console status because it interferes with debug output
                console.WriteLine(status);
                return await SearchAsync(settings, cancellationToken);
            }

            return await console.Status().StartAsync(status, async _ => await SearchAsync(settings, cancellationToken));
        }
        catch (LdapException exception)
        {
            var errorStyle = new Style(Color.Red, decoration: Decoration.Bold);
            console.WriteLine(exception.Message, errorStyle);
            if (!string.IsNullOrEmpty(exception.ServerErrorMessage))
            {
                console.WriteLine(exception.ServerErrorMessage, errorStyle);
            }
            return 2;
        }
    }

    private async Task<int> SearchAsync(Settings settings, CancellationToken cancellationToken)
    {
        using var connection = await CreateConnectionAsync(settings, cancellationToken);
        if (settings.CanonicalizeHostName.IsSet)
        {
            connection.SessionOptions.CanonicalizeHostName = settings.CanonicalizeHostName.Value;
        }
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

        var ldap = new LdapSearcher(connection);

        var exitCode = 1;
        var searchBase = await GetSearchBaseAsync(settings, connection, cancellationToken);
        await foreach (var searchResult in ldap.SearchAsync(searchBase, settings.Filter, settings.Attributes).WithCancellation(cancellationToken))
        {
            exitCode = 0;
            WriteSearchResult(searchResult);
        }

        return exitCode;
    }

    private static async Task<string> GetSearchBaseAsync(Settings settings, LdapConnection ldapConnection, CancellationToken cancellationToken)
    {
        if (settings.SearchBase != null)
        {
            return settings.SearchBase;
        }

        var ruleProvider = new SimpleHttpRuleProvider();
        await ruleProvider.BuildAsync(cancellationToken: cancellationToken);

        var domainParser = new DomainParser(ruleProvider);
        var server = GetServer(ldapConnection);
        var domainInfo = domainParser.Parse(server) ?? throw new InvalidOperationException($"Could not parse {server} as a DomainInfo");
        var registrableDomain = domainInfo.RegistrableDomain ?? throw new InvalidOperationException($"Could not determine registrable domain for {server}");
        var searchBase = registrableDomain.Split('.').Select(s => $"DC={s}").Aggregate((a, b) => $"{a},{b}");
        return searchBase;
    }

    private async Task<LdapConnection> CreateConnectionAsync(Settings settings, CancellationToken cancellationToken)
    {
        if (settings.Host != null)
        {
            return new LdapConnection(settings.Host);
        }

        var dnsClient = new LookupClient();
        var userDnsDomain = await GetUserDnsDomainAsync(cancellationToken);
        var hostEntries = await dnsClient.ResolveServiceAsync(userDnsDomain, "ldap", ProtocolType.Tcp);
        if (hostEntries.Length == 0)
        {
            throw new InvalidOperationException($"No LDAP service found for {userDnsDomain}");
        }

        var ldapConnection = await hostEntries.GetFastestAsync(ConnectAsync, cancellationToken);
        console.WriteLine($"Connected to LDAP server {GetServer(ldapConnection)}");
        return ldapConnection;
    }

    private static async Task<LdapConnection> ConnectAsync(ServiceHostEntry hostEntry, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        // https://jvns.ca/blog/2022/09/12/why-do-domain-names-end-with-a-dot-/
        var server = hostEntry.HostName.TrimEnd('.');
        await client.ConnectAsync(server, hostEntry.Port, cancellationToken);
        return new LdapConnection(new LdapDirectoryIdentifier(server, hostEntry.Port));
    }

    private static string GetServer(LdapConnection connection) => ((LdapDirectoryIdentifier)connection.Directory).Servers.Single();

    private static async Task<string> GetUserDnsDomainAsync(CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? throw new InvalidOperationException("The USERDNSDOMAIN environment variable is not set");
        }

        var principal = GssApi.GetPrincipal();
        if (principal == null)
        {
            if (OperatingSystem.IsMacOS())
            {
                principal = await ExtensibleSingleSignOn.GetRealmAsync(cancellationToken);
            }
            else
            {
                throw new InvalidOperationException("No principal found. Try to run 'kinit' or 'kinit <username>@<realm>'");
            }
        }

        return principal.Split('@').Last();
    }

    private void WriteSearchResult(SearchResultEntry searchResult)
    {
        console.WriteLine(searchResult.DistinguishedName, new Style(Color.DeepSkyBlue1, decoration: Decoration.Underline));
        foreach (var entry in searchResult.Attributes.Cast<DictionaryEntry>().Where(e => !string.Equals(e.Key as string, "distinguishedName", StringComparison.OrdinalIgnoreCase)).OrderBy(e => e.Key))
        {
            var attribute = (DirectoryAttribute)(entry.Value ?? throw new InvalidDataException($"Attribute for {entry.Key} is missing"));
            var values = attribute.GetValues(typeof(byte[]));
            console.MarkupLineInterpolated($"  [b]{attribute.Name}[/]");
            foreach (byte[] value in values)
            {
                try
                {
                    var text = ValidatingUtf8.GetString(value);
                    if (text.Length == 18 && long.TryParse(text, NumberStyles.None, NumberFormatInfo.InvariantInfo, out var fileTime))
                    {
                        var date = DateTime.FromFileTime(fileTime);
                        console.MarkupLineInterpolated($"    {date:F} ({text})");
                    }
                    else
                    {
                        using var reader = new StringReader(text);
                        while (reader.ReadLine() is { } line)
                        {
                            console.WriteLine($"    {line}");
                        }
                    }
                }
                catch (DecoderFallbackException)
                {
                    if (SecurityIdentifier.TryParse(value, out var sid))
                    {
                        console.WriteLine($"    {sid}");
                    }
                    else if (value.Length == 16)
                    {
                        console.WriteLine($"    {new Guid(value, bigEndian: false):B}");
                    }
                    else
                    {
                        console.WriteLine($"    {Convert.ToHexString(value)}");
                    }
                }
            }
        }
    }

    // Heavily adapted from https://github.com/jborean93/PSOpenAD/blob/bdc83ad3e3adc2ccff352150e560d4fc9b698453/src/PSOpenAD/Security/SecurityIdentifier.cs
    private static class SecurityIdentifier
    {
        public static bool TryParse(ReadOnlySpan<byte> data, [NotNullWhen(true)] out string? sid)
        {
            if (data.Length < 8)
            {
                sid = null;
                return false;
            }

            var revision = data[0];
            var subAuthorityCount = data[1];
            if (revision != 1 || data.Length != 8 + subAuthorityCount * 4)
            {
                sid = null;
                return false;
            }

            Span<byte> rawAuthority = stackalloc byte[8];
            data[2..8].CopyTo(rawAuthority[2..]);
            var identifierAuthority = BinaryPrimitives.ReadUInt64BigEndian(rawAuthority);

            var sidBuilder = new StringBuilder($"S-{revision}-{identifierAuthority}");
            for (var i = 0; i < subAuthorityCount; i++)
            {
                sidBuilder.Append($"-{BitConverter.ToUInt32(data[(8 + i * 4)..])}");
            }

            sid = sidBuilder.ToString();
            return true;
        }
    }
}