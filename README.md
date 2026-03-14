This project is used to work on a fix for [LdapConnection throws `LdapException: The feature is not supported` when using Negotiate or Kerberos authentication (#109449)](https://github.com/dotnet/runtime/issues/109449)

The [System.DirectoryServices.Protocols.csproj](https://github.com/dotnet/runtime/blob/v8.0.10/src/libraries/System.DirectoryServices.Protocols/src/System.DirectoryServices.Protocols.csproj) project uses the [Arcade SDK](https://github.com/dotnet/arcade/blob/main/Documentation/ArcadeSdk.md) so it's pretty difficult to use by referencing it in a solution. Trying to do so results in an error.

>  [MSB4236] The SDK 'Microsoft.DotNet.Arcade.Sdk' specified could not be found. $(HOME)/Projects/dotnet/runtime/Directory.Build.props at (86:31)

So in order to build the `System.DirectoryServices.Protocols` package from source, I copied the contents from the original csproj and adapted a few things to make it compile. Note that the dotnet [runtime](https://github.com/dotnet/runtime/) repository needs to be cloned in the same directory as this repository for the source file to be available.

## References

* [LDAP authentication in ASP.NET Core MVC](https://decovar.dev/blog/2022/06/16/dotnet-ldap-authentication/)
* [LDAP vs. Active Directory: What's the Difference?](https://www.okta.com/identity-101/ldap-vs-active-directory/)
* [ldapsearch command suddenly stopped working on my Mac](https://superuser.com/questions/1842687/ldapsearch-command-suddenly-stopped-working-on-my-mac/1935578#1935578)
* [PSOpenAD - Cross-platform PowerShell module alternative to Microsoft's Active Directory module](https://github.com/jborean93/PSOpenAD)
