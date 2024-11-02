namespace System.DirectoryServices.Protocols;

internal partial class SR
{
    public static string Format(string format, params object[] args) => string.Format(format, args);
}