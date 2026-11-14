using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ldap;

internal static class LdapConnectionExtensions
{
    public static async Task<SearchResponse> SearchAsync(this LdapConnection connection, SearchRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            return (SearchResponse)await connection.SendRequestAsync(request, cancellationToken);
        }
        catch (LdapException exception)
        {
            // The default LdapException message is missing crucial information to properly diagnose issues
            var server = (connection.Directory as LdapDirectoryIdentifier)?.Servers.FirstOrDefault() ?? "???";
            throw new LdapException(exception.ErrorCode, $"[Error {exception.ErrorCode} on {server}] {exception.Message} {exception.ServerErrorMessage}".TrimEnd(), exception);
        }
    }

    private static Task<DirectoryResponse> SendRequestAsync(this LdapConnection connection, DirectoryRequest request, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<DirectoryResponse>(TaskCreationOptions.RunContinuationsAsynchronously);

        CancellationTokenRegistration ctr = default;

        try
        {
            var asyncResult = connection.BeginSendRequest(request, PartialResultProcessing.NoPartialResultSupport, ar =>
                {
                    try
                    {
                        // ReSharper disable once AccessToModifiedClosure
                        // ReSharper disable once AccessToDisposedClosure
                        ctr.Dispose();

                        var response = connection.EndSendRequest(ar);
                        tcs.TrySetResult(response);
                    }
                    catch (Exception exception)
                    {
                        tcs.TrySetException(exception);
                    }
                },
                state: null);

            if (cancellationToken.CanBeCanceled)
            {
                ctr = cancellationToken.Register(() =>
                {
                    try
                    {
                        connection.Abort(asyncResult);
                        tcs.TrySetCanceled(cancellationToken);
                    }
                    catch (Exception exception)
                    {
                        tcs.TrySetException(exception);
                    }
                });
            }
        }
        catch (Exception exception)
        {
            ctr.Dispose();
            tcs.TrySetException(exception);
        }

        return tcs.Task;
    }
}