using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ldap;

/// <summary>
/// Provides extensions to work with <see cref="Task"/> objects.
/// </summary>
internal static class TaskExtensions
{
    extension<TSource>(IEnumerable<TSource> source)
    {
        /// <summary>
        /// Get the fastest task to complete successfully. Once the fastest task has completed successfully, all other pending tasks are automatically canceled.
        /// Tasks that fail with an exception are ignored, unless all tasks from the <paramref name="source"/> fail.
        /// </summary>
        /// <param name="task">A task that transforms an input of type <typeparamref name="TSource"/> into an output of type <typeparamref name="TResult"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to cancel the operation.</param>
        /// <typeparam name="TResult">The result returned by the fastest task of the <paramref name="source"/>.</typeparam>
        /// <returns>The fastest task to complete successfully.</returns>
        /// <exception cref="AggregateException">None of the tasks complete successfully.</exception>
        public async Task<TResult> GetFastestAsync<TResult>(Func<TSource, CancellationToken, Task<TResult>> task, CancellationToken cancellationToken = default)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var tasks = source.Select(async e =>
            {
                try
                {
                    return (Result: await task(e, cts.Token).ConfigureAwait(false), Exception: (Exception?)null);
                }
                catch (Exception exception)
                {
                    return (Result: default!, Exception: exception);
                }
            });

            var exceptions = new List<Exception>();
            await foreach (var completedTask in Task.WhenEach(tasks).WithCancellation(cts.Token).ConfigureAwait(false))
            {
                var taskResult = await completedTask.ConfigureAwait(false);
                if (taskResult.Exception == null)
                {
                    await cts.CancelAsync().ConfigureAwait(false);
                    return taskResult.Result;
                }

                exceptions.Add(taskResult.Exception);
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (exceptions.Count == 0)
            {
                throw new ArgumentException("The source cannot be empty", nameof(source));
            }

            throw new AggregateException(exceptions);
        }
    }
}