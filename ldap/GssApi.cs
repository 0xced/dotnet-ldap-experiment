using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace ldap;

[SuppressMessage("ReSharper", "InconsistentNaming", Justification = "Naming is consistent with the native library")]
public static class GssApi
{
    private const string libGssApi = "libgssapi_krb5";

    private const uint GSS_S_COMPLETE = 0;
    private const uint GSS_S_NO_CRED = 0x70000;

    private const int GSS_C_INITIATE = 1;

    private static readonly IntPtr GSS_C_NO_NAME = IntPtr.Zero;
    private static readonly IntPtr GSS_C_NO_OID_SET = IntPtr.Zero;

    [StructLayout(LayoutKind.Sequential)]
    private struct gss_buffer_desc
    {
        public UIntPtr length;
        public IntPtr value;
    }

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_acquire_cred(out uint minor_status, IntPtr desired_name, uint time_req, IntPtr desired_mechs, int cred_usage, out IntPtr output_cred_handle, IntPtr actual_mechs, IntPtr time_rec);

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_inquire_cred(out uint minor_status, IntPtr cred_handle, out IntPtr name, IntPtr lifetime, IntPtr cred_usage, IntPtr mechanisms);

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_display_name(out uint minor_status, IntPtr input_name, out gss_buffer_desc output_buffer, IntPtr output_name_type);

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_release_buffer(out uint minor_status, ref gss_buffer_desc buffer);

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_release_name(out uint minor_status, ref IntPtr name);

    [DllImport(libGssApi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint gss_release_cred(out uint minor_status, ref IntPtr cred_handle);

    public static string? GetPrincipal()
    {
        var cred = gss_acquire_cred();
        var name = gss_inquire_cred(cred);
        if (name == IntPtr.Zero)
        {
            return null;
        }

        var nameBuffer = gss_display_name(name, cred);
        var principal = Marshal.PtrToStringUTF8(nameBuffer.value, (int)nameBuffer.length);

        gss_release_buffer(out _, ref nameBuffer);
        gss_release_name(out _, ref name);
        gss_release_cred(out _, ref cred);

        return principal;
    }

    private static IntPtr gss_acquire_cred()
    {
        var major = gss_acquire_cred(out var minor, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_INITIATE, out var cred, IntPtr.Zero, IntPtr.Zero);
        return major == GSS_S_COMPLETE ? cred : throw new InvalidOperationException($"gss_acquire_cred failed ({major:X}/{minor:X})");
    }

    private static IntPtr gss_inquire_cred(IntPtr cred)
    {
        var major = gss_inquire_cred(out var minor, cred, out var name, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (major == GSS_S_NO_CRED)
        {
            gss_release_cred(out _, ref cred);
            return name;
        }

        if (major != GSS_S_COMPLETE)
        {
            gss_release_cred(out _, ref cred);
            throw new InvalidOperationException($"gss_inquire_cred failed ({major:X}/{minor:X})");
        }

        return name;
    }

    private static gss_buffer_desc gss_display_name(IntPtr name, IntPtr cred)
    {
        var major = gss_display_name(out var minor, name, out var nameBuffer, IntPtr.Zero);
        if (major != GSS_S_COMPLETE)
        {
            gss_release_name(out _, ref name);
            gss_release_cred(out _, ref cred);
            throw new InvalidOperationException($"gss_display_name failed ({major:X}/{minor:X})");
        }

        return nameBuffer;
    }
}