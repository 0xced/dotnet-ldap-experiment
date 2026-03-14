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

        [LibraryImport(OpenLdap, EntryPoint = "ldap_get_option")]
        public static partial int ldap_get_option_bool(SafeHandle ldapHandle, int option, [MarshalAs(UnmanagedType.Bool)] out bool outValue);

        [LibraryImport(OpenLdap, EntryPoint = "ldap_set_option", SetLastError = true)]
        public static partial int ldap_set_option_bool(SafeHandle ld, int option, [MarshalAs(UnmanagedType.Bool)] bool value);
    }

    // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/OSX/Interop.Libraries.cs#L14
    private static partial class MacOS
    {
        private const string OpenLdap = "libldap.dylib";

        [LibraryImport(OpenLdap, EntryPoint = "ldap_set_option", SetLastError = true)]
        public static partial int ldap_set_option_int(IntPtr ld, int option, ref int inValue);

        [LibraryImport(OpenLdap, EntryPoint = "ldap_get_option")]
        public static partial int ldap_get_option_bool(SafeHandle ldapHandle, int option, [MarshalAs(UnmanagedType.Bool)] out bool outValue);

        [LibraryImport(OpenLdap, EntryPoint = "ldap_set_option", SetLastError = true)]
        public static partial int ldap_set_option_bool(SafeHandle ld, int option, [MarshalAs(UnmanagedType.Bool)] bool value);
    }

    // https://github.com/dotnet/runtime/blob/v10.0.4/src/libraries/Common/src/Interop/Windows/Interop.Libraries.cs#L40
    private static partial class Windows
    {
        private const string Wldap32 = "wldap32.dll";

        [LibraryImport(Wldap32, EntryPoint = "ldap_set_optionW")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial int ldap_set_option_int(IntPtr ldapHandle, int option, ref int inValue);

        [LibraryImport(Wldap32, EntryPoint = "ldap_get_optionW")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial int ldap_get_option_bool(SafeHandle ldapHandle, int option, [MarshalAs(UnmanagedType.Bool)] out bool outValue);

        [LibraryImport(Wldap32, EntryPoint = "ldap_set_optionW")]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        public static partial int ldap_set_option_bool(SafeHandle ldapHandle, int option, [MarshalAs(UnmanagedType.Bool)] bool value);
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

    public static bool GetSaslNoCanon(SafeHandle ldapHandle)
    {
        // ReSharper disable once InconsistentNaming
        // https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_13/include/ldap.h#L203
        const int LDAP_OPT_X_SASL_NOCANON = 0x610b;
        bool result;

        if (OperatingSystem.IsMacOS())
            MacOS.ldap_get_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, out result);
        else if (OperatingSystem.IsWindows())
            Windows.ldap_get_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, out result);
        else
            Linux.ldap_get_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, out result);

        return result;
    }

    public static int SetSaslNoCanon(SafeHandle ldapHandle, bool value)
    {
        // ReSharper disable once InconsistentNaming
        // https://github.com/openldap/openldap/blob/OPENLDAP_REL_ENG_2_6_13/include/ldap.h#L203
        const int LDAP_OPT_X_SASL_NOCANON = 0x610b;

        if (OperatingSystem.IsMacOS())
            return MacOS.ldap_set_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, value);

        if (OperatingSystem.IsWindows())
            return Windows.ldap_set_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, value);

        return Linux.ldap_set_option_bool(ldapHandle, LDAP_OPT_X_SASL_NOCANON, value);
    }
}