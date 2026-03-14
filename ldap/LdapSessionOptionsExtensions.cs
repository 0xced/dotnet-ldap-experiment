using System;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ldap;

internal static class LdapSessionOptionsExtensions
{
    private static readonly FieldInfo? LdapHandleField;

    static LdapSessionOptionsExtensions()
    {
        // Unfortunately, UnsafeAccessor can't be used on a field with an internal class
        // See https://andrewlock.net/exploring-dotnet-10-preview-features-9-easier-reflection-with-unsafeaccessortype/#2-unable-to-represent-field-return-types
        // and https://github.com/dotnet/runtime/issues/119664
        LdapHandleField = typeof(LdapConnection).GetField("_ldapHandle", BindingFlags.Instance | BindingFlags.NonPublic);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_connection")]
    private static extern ref LdapConnection _connection(LdapSessionOptions options);

    extension(LdapSessionOptions options)
    {
        private SafeHandle GetLdapHandle()
        {
            var connection = _connection(options);
            var ldapHandleField = LdapHandleField ?? throw new MissingFieldException(typeof(LdapConnection).FullName, "_ldapHandle");
            var handle = ldapHandleField.GetValue(connection);
            return handle as SafeHandle ?? throw new InvalidCastException($"Unable to cast object of type '{handle?.GetType()}' to type '{typeof(SafeHandle)}'.");
        }

        /// <summary>
        /// Configures whether the LDAP host name should be canonicalized or not.
        /// I.e., the host name is resolved to an IP address, then a reverse DNS query is performed on that IP, and the result of that reverse DNS query is used as the host name for SASL authentication.
        /// <para/>
        /// Setting <see cref="CanonicalizeHostName"/> to <see langword="false"/> is equivalent to configuring <c>SASL_NOCANON true</c> in the <c>ldaprc</c> or <c>.ldaprc</c> configuration file.
        /// </summary>
        /// <remarks>
        /// This is an implementation for <see href="https://github.com/dotnet/runtime/issues/125454">[API Proposal]: Add a new CanonicalizeHostName property on LdapSessionOptions.</see>
        /// Note that the real implementation would not require using reflection.
        /// </remarks>
        public bool CanonicalizeHostName
        {
            get => !LdapNative.GetSaslNoCanon(options.GetLdapHandle());
            set => _ = LdapNative.SetSaslNoCanon(options.GetLdapHandle(), !value);
        }
    }
}