using System.Text.Json;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal static class ManagedPluginExecutor
{
    internal static async ValueTask<ManagedExecution> ExecuteAsync(
        LoadedManagedPlugin loaded,
        PluginHostContext host,
        ExactBinaryImage binary,
        HostInput input,
        CancellationToken cancellationToken)
    {
        PluginRejection? rejection = null;
        var success = false;
        var invocationAbandoned = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var initialization = new PluginInitialization(
                input.Hello.SessionId,
                PluginApi.Version,
                input.Hello.GrantedPermissions.ToArray(),
                new PluginLimits(
                    checked((long)input.Hello.Limits.MaxMemoryBytes),
                    input.Hello.Limits.MaxMessageBytes,
                    TimeSpan.FromMilliseconds(input.Hello.Limits.RequestTimeoutMilliseconds)),
                RequestOptions(input.Request.Payload));
            await InvokeInPhaseAsync(
                host,
                PluginHostPhase.Initialization,
                "initialization",
                () => loaded.Plugin.InitializeAsync(host, initialization, cancellationToken),
                cancellationToken).ConfigureAwait(false);

            var health = await InvokeInPhaseAsync(
                host,
                PluginHostPhase.HealthCheck,
                "health check",
                () => loaded.Plugin.CheckHealthAsync(cancellationToken),
                cancellationToken).ConfigureAwait(false);
            if (health is null || health.State == PluginHealthState.Unhealthy)
            {
                throw new HostException("managed plugin reported unhealthy status");
            }

            var analysisRequest = new AnalysisRequest(
                input.Request.Id,
                binary.ToSdkIdentity(input.Bootstrap.Binary),
                RequestPhase(input.Request.Payload),
                RequestOptions(input.Request.Payload),
                RequestBaseAnalysis(
                    input.Request.Payload,
                    input.Hello.GrantedPermissions));
            await InvokeInPhaseAsync(
                host,
                PluginHostPhase.Analysis,
                "analysis",
                () => loaded.Plugin.AnalyzeAsync(analysisRequest, cancellationToken),
                cancellationToken).ConfigureAwait(false);
            success = true;
        }
        catch (PluginInvocationCancelledException exception)
        {
            invocationAbandoned |= exception.Abandoned;
            rejection = CancelledRejection();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            rejection = CancelledRejection();
        }
        catch (PluginLifecycleException exception)
            when (exception.InnerException is IHostServiceFailure)
        {
            var failure = (IHostServiceFailure)exception.InnerException;
            rejection = new PluginRejection(
                failure.Code,
                BoundedMessage(exception.InnerException.Message));
        }
        catch (Exception exception) when (exception is IHostServiceFailure)
        {
            var failure = (IHostServiceFailure)exception;
            rejection = new PluginRejection(
                failure.Code,
                BoundedMessage(exception.Message));
        }
        catch (PluginLifecycleException exception)
            when (exception.InnerException is HostException hostException)
        {
            rejection = new PluginRejection(
                "invalid-argument",
                BoundedMessage(hostException.Message));
        }
        catch (HostException exception)
        {
            rejection = new PluginRejection("invalid-argument", BoundedMessage(exception.Message));
        }
        catch (PluginLifecycleException)
        {
            rejection = new PluginRejection("internal", "managed plugin lifecycle failed");
        }
        catch (Exception)
        {
            rejection = new PluginRejection("internal", "managed plugin lifecycle failed");
        }
        finally
        {
            if (cancellationToken.IsCancellationRequested)
            {
                success = false;
                rejection = CancelledRejection();
            }

            // Once an invocation has outlived its deadline it can still be
            // executing arbitrary plugin code. Do not start cleanup beside
            // that abandoned invocation. The disposable parent process is the
            // authoritative teardown boundary; closing the phase lease below
            // immediately revokes every host service in the meantime.
            if (!invocationAbandoned && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await InvokeInPhaseAsync(
                        host,
                        PluginHostPhase.Shutdown,
                        "shutdown",
                        () => loaded.Plugin.ShutdownAsync(cancellationToken),
                        cancellationToken).ConfigureAwait(false);
                }
                catch (PluginInvocationCancelledException exception)
                {
                    invocationAbandoned |= exception.Abandoned;
                    success = false;
                    rejection = CancelledRejection();
                }
                catch (OperationCanceledException) when (
                    cancellationToken.IsCancellationRequested)
                {
                    success = false;
                    rejection = CancelledRejection();
                }
                catch
                {
                    success = false;
                    rejection = CleanupRejection();
                }
            }

            if (cancellationToken.IsCancellationRequested)
            {
                success = false;
                rejection = CancelledRejection();
            }

            if (!invocationAbandoned && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await InvokeInPhaseAsync(
                        host,
                        PluginHostPhase.Disposal,
                        "disposal",
                        loaded.Plugin.DisposeAsync,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (PluginInvocationCancelledException exception)
                {
                    invocationAbandoned |= exception.Abandoned;
                    success = false;
                    rejection = CancelledRejection();
                }
                catch (OperationCanceledException) when (
                    cancellationToken.IsCancellationRequested)
                {
                    success = false;
                    rejection = CancelledRejection();
                }
                catch
                {
                    success = false;
                    rejection = CleanupRejection();
                }
            }
        }

        if (!success && rejection is null)
        {
            rejection = new PluginRejection("internal", "managed plugin cleanup failed");
        }
        return new ManagedExecution(
            loaded.Descriptor,
            host.Finish(success && rejection is null),
            rejection);
    }

    private static async ValueTask InvokeInPhaseAsync(
        PluginHostContext host,
        PluginHostPhase phase,
        string description,
        Func<ValueTask> operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lease = host.EnterPhase(phase);
        try
        {
            await InvokeAsync(
                description,
                operation,
                lease.Dispose,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // On timeout the invocation task can still be running. Close its
            // services immediately; Dispose is intentionally idempotent when
            // the task's completion path already closed them.
            lease.Dispose();
        }
    }

    private static async ValueTask<T> InvokeInPhaseAsync<T>(
        PluginHostContext host,
        PluginHostPhase phase,
        string description,
        Func<ValueTask<T>> operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lease = host.EnterPhase(phase);
        try
        {
            return await InvokeAsync(
                description,
                operation,
                lease.Dispose,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lease.Dispose();
        }
    }

    private static async ValueTask InvokeAsync(
        string phase,
        Func<ValueTask> operation,
        Action closeServices,
        CancellationToken cancellationToken)
    {
        Task? task = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            task = Task.Run(async () =>
            {
                try
                {
                    await operation().ConfigureAwait(false);
                }
                finally
                {
                    // Make phase closure part of task completion so a detached
                    // callback cannot use the scheduler gap before our await
                    // continuation resumes.
                    closeServices();
                }
            }, cancellationToken);
            ObserveFailure(task);
            await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new PluginInvocationCancelledException(
                phase,
                task is { IsCompleted: false },
                cancellationToken);
        }
        catch (Exception exception)
        {
            throw new PluginLifecycleException(phase, exception);
        }
    }

    private static async ValueTask<T> InvokeAsync<T>(
        string phase,
        Func<ValueTask<T>> operation,
        Action closeServices,
        CancellationToken cancellationToken)
    {
        Task<T>? task = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            task = Task.Run(async () =>
            {
                try
                {
                    return await operation().ConfigureAwait(false);
                }
                finally
                {
                    closeServices();
                }
            }, cancellationToken);
            ObserveFailure(task);
            return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new PluginInvocationCancelledException(
                phase,
                task is { IsCompleted: false },
                cancellationToken);
        }
        catch (Exception exception)
        {
            throw new PluginLifecycleException(phase, exception);
        }
    }

    private static void ObserveFailure(Task task)
    {
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted |
                TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static PluginRejection CancelledRejection() =>
        new("cancelled", "managed plugin deadline expired");

    private static PluginRejection CleanupRejection() =>
        new("internal", "managed plugin cleanup failed");

    private static string RequestPhase(JsonElement payload)
    {
        if (payload.TryGetProperty("phase", out var phase) &&
            phase.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(phase.GetString()))
        {
            return phase.GetString()!;
        }
        return "analysis";
    }

    private static JsonElement RequestOptions(JsonElement payload)
    {
        if (!payload.TryGetProperty("options", out var options))
        {
            return JsonSerializer.SerializeToElement(new { });
        }
        if (options.ValueKind != JsonValueKind.Object)
        {
            throw new HostException("managed request options must be an object");
        }
        return options.Clone();
    }

    private static JsonElement? RequestBaseAnalysis(
        JsonElement payload,
        IReadOnlyList<string> grantedPermissions)
    {
        if (!payload.TryGetProperty("base_analysis", out var baseAnalysis))
        {
            return null;
        }
        if (!grantedPermissions.Contains("symbols.read", StringComparer.Ordinal))
        {
            throw new HostException(
                "managed request includes base analysis without symbols.read permission");
        }
        if (baseAnalysis.ValueKind != JsonValueKind.Object)
        {
            throw new HostException("managed base analysis must be an object");
        }
        return baseAnalysis.Clone();
    }

    private static string BoundedMessage(string message)
    {
        const int limit = 512;
        if (message.Length <= limit)
        {
            return message;
        }
        return string.Concat(message.AsSpan(0, limit - 3), "...");
    }

    private sealed class PluginInvocationCancelledException(
        string phase,
        bool abandoned,
        CancellationToken cancellationToken)
        : OperationCanceledException(
            $"managed plugin {phase} exceeded its execution boundary",
            innerException: null,
            cancellationToken)
    {
        internal bool Abandoned { get; } = abandoned;
    }
}
