using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ldap;

// Additions to https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Linux/OpenLdap/Interop.Ldap.cs
// and https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Windows/Wldap32/Interop.Ldap.cs
internal static partial class LdapNative
{
    // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Linux/Interop.Libraries.cs#L12
    private static partial class Linux
    {
        private const string OpenLdap = "libldap.so.2";

        [LibraryImport(OpenLdap, EntryPoint = "ldap_set_option", SetLastError = true)]
        public static partial int ldap_set_option_int(IntPtr ld, int option, ref int inValue);
    }

    // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/OSX/Interop.Libraries.cs#L14
    private static partial class MacOS
    {
        private const string OpenLdap = "libldap.dylib";

        [LibraryImport(OpenLdap, EntryPoint = "ldap_set_option", SetLastError = true)]
        public static partial int ldap_set_option_int(IntPtr ld, int option, ref int inValue);
    }

    // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Windows/Interop.Libraries.cs#L40
    private static partial class Windows
    {
        private const string Wldap32 = "wldap32.dll";

        [LibraryImport(Wldap32, EntryPoint = "ldap_set_optionW")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial int ldap_set_option_int(IntPtr ldapHandle, int option, ref int inValue);
    }

    public static int SetDebugLevel(int level)
    {
        // ReSharper disable once InconsistentNaming
        // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Interop.Ldap.cs#L158
        const int LDAP_OPT_DEBUG_LEVEL = 0x5001;

        if (OperatingSystem.IsMacOS())
            return MacOS.ldap_set_option_int(IntPtr.Zero, LDAP_OPT_DEBUG_LEVEL, ref level);

        if (OperatingSystem.IsWindows())
            return Windows.ldap_set_option_int(IntPtr.Zero, LDAP_OPT_DEBUG_LEVEL, ref level);

        return Linux.ldap_set_option_int(IntPtr.Zero, LDAP_OPT_DEBUG_LEVEL, ref level);
    }
}