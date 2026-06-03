using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ldap;

internal static class TaskExtensions
{
    // See https://stackoverflow.com/questions/49313367/task-whenany-for-non-faulted-tasks/49313971#49313971
    public static async Task<TResult> GetFastestAsync<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, CancellationToken, Task<TResult>> task, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = source.Select(e => task(e, cts.Token)).ToHashSet();
        var exceptions = new List<Exception>();
        do
        {
            var completedTask = await Task.WhenAny(tasks);
            if (completedTask.IsCompletedSuccessfully)
            {
                await cts.CancelAsync();
                return await completedTask;
            }

            if (completedTask.Exception != null)
            {
                exceptions.AddRange(completedTask.Exception.InnerExceptions);
            }
            tasks.Remove(completedTask);
        } while (tasks.Count > 0);

        throw new AggregateException(exceptions);
    }
}