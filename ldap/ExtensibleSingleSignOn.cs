using System;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;

namespace ldap;

[SupportedOSPlatform("macOS")]
public static class ExtensibleSingleSignOn
{
    public static async Task<string> GetRealmAsync(CancellationToken cancellationToken)
    {
        var path = $"/Library/Managed Preferences/{Environment.UserName}/complete.plist";
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read);
        var document = await XDocument.LoadAsync(stream, LoadOptions.None, cancellationToken);
        var realmXpath = $"/plist/dict/{Dict("com.apple.extensiblesso")}/{Dict("Realm")}/{String("value")}";
        var realm = document.XPathSelectElement(realmXpath);
        return realm?.Value ?? throw new InvalidDataException($"Realm not found in {path}");
    }

    private static string Dict(string key) => $"key[text()='{key}']/following-sibling::dict[1]";

    private static string String(string key) => $"key[text()='{key}']/following-sibling::string[1]";
}