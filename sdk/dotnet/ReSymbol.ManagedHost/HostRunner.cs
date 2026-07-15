using System.Text;

namespace ReSymbol.ManagedHost;

internal static class HostRunner
{
    // Fixed, versioned stderr contract consumed by the trusted parent. The
    // parent removes exactly one leading instance before exposing diagnostics.
    // It is published before the first assembly-load operation because module
    // initializers and type discovery can execute plugin-controlled code.
    internal const string LoadAttemptedMarker =
        "@resymbol-managed-host/load-attempted/v1@\n";

    internal static async Task<int> RunProcessAsync(
        IReadOnlyList<string> arguments,
        Stream input,
        Stream output,
        TextWriter diagnostics,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var paths = HostPaths.Parse(arguments);
            EnsureEnabled(paths.PluginRoot);
            var hostInput = await HostInputReader.ReadAsync(input, cancellationToken)
                .ConfigureAwait(false);
            using var deadline = CreateDeadline(hostInput, cancellationToken);

            var assemblies = await AssemblySnapshot.CreateAsync(
                paths.PluginRoot,
                hostInput.Bootstrap,
                hostInput.Hello.Limits.MaxMemoryBytes,
                deadline.Token).ConfigureAwait(false);
            var assemblyBytes = checked((ulong)assemblies.TotalBytes);
            if (assemblyBytes > hostInput.Hello.Limits.MaxMemoryBytes)
            {
                throw new HostException(
                    "managed assembly closure exceeds the verified-snapshot byte budget");
            }
            var remainingSnapshotBytes =
                hostInput.Hello.Limits.MaxMemoryBytes - assemblyBytes;
            var binary = await ExactBinaryImage.OpenAsync(
                paths.BinaryPath,
                hostInput.Bootstrap,
                remainingSnapshotBytes,
                deadline.Token).ConfigureAwait(false);
            EnsureEnabled(paths.PluginRoot);
            await PluginArtifactFingerprint.VerifyAsync(
                paths.PluginRoot,
                hostInput.Bootstrap.ExpectedArtifactSha256,
                deadline.Token).ConfigureAwait(false);
            EnsureEnabled(paths.PluginRoot);

            deadline.Token.ThrowIfCancellationRequested();
            await PublishLoadAttemptedMarkerAsync(diagnostics).ConfigureAwait(false);
            // The marker flush can block long enough for the deadline to
            // expire. Check again and pass the token to Task.Run so a cancelled
            // request cannot begin plugin loading in the final scheduler gap.
            deadline.Token.ThrowIfCancellationRequested();
            var loadTask = Task.Run(() => ManagedPluginLoader.Load(
                assemblies,
                hostInput), deadline.Token);
            ObserveFailure(loadTask);
            var loaded = await loadTask.WaitAsync(deadline.Token).ConfigureAwait(false);
            ManagedExecution execution;
            try
            {
                var pluginHost = new PluginHostContext(binary, hostInput);
                execution = await ManagedPluginExecutor.ExecuteAsync(
                    loaded,
                    pluginHost,
                    binary,
                    hostInput,
                    deadline.Token).ConfigureAwait(false);

                // No buffered event may escape if either the analyzed bytes or
                // any assembly in the host-owned closure drifted during execution.
                await assemblies.VerifySourcesAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                await binary.VerifySourceAsync(CancellationToken.None).ConfigureAwait(false);
                await PluginArtifactFingerprint.VerifyAsync(
                    paths.PluginRoot,
                    hostInput.Bootstrap.ExpectedArtifactSha256,
                    CancellationToken.None).ConfigureAwait(false);
                EnsureEnabled(paths.PluginRoot);
            }
            finally
            {
                loaded.LoadContext.Unload();
            }

            var encoded = WireOutput.EncodeExecution(
                execution,
                hostInput.Request.Id,
                hostInput.Hello.Limits.MaxMessageBytes,
                hostInput.Bootstrap.OutputLimits.MaxStdoutBytes);
            await output.WriteAsync(encoded, CancellationToken.None).ConfigureAwait(false);
            await output.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            await diagnostics.WriteLineAsync(
                $"managed host error: {BoundedDiagnostic(exception)}").ConfigureAwait(false);
            await diagnostics.FlushAsync().ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task PublishLoadAttemptedMarkerAsync(TextWriter diagnostics)
    {
        await diagnostics.WriteAsync(LoadAttemptedMarker).ConfigureAwait(false);
        await diagnostics.FlushAsync().ConfigureAwait(false);
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

    private static CancellationTokenSource CreateDeadline(
        HostInput input,
        CancellationToken outerToken)
    {
        var timeout = TimeSpan.FromMilliseconds(
            input.Hello.Limits.RequestTimeoutMilliseconds);
        if (input.Bootstrap.DeadlineUnixMilliseconds is long absoluteMilliseconds)
        {
            var remaining = DateTimeOffset.FromUnixTimeMilliseconds(absoluteMilliseconds) -
                DateTimeOffset.UtcNow;
            if (remaining < timeout)
            {
                timeout = remaining;
            }
        }
        var source = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        if (timeout <= TimeSpan.Zero)
        {
            source.Cancel();
        }
        else
        {
            source.CancelAfter(timeout);
        }
        return source;
    }

    private static void EnsureEnabled(string pluginRoot)
    {
        var disabled = Path.Combine(pluginRoot, "plugin.disabled");
        if (File.Exists(disabled) || Directory.Exists(disabled))
        {
            throw new HostException("plugin package is disabled");
        }
    }

    private static string BoundedDiagnostic(Exception exception)
    {
        const int limit = 4096;
        var source = $"{exception.GetType().Name}: {exception.Message}";
        var builder = new StringBuilder(Math.Min(source.Length, limit));
        var pendingSpace = false;
        foreach (var character in source)
        {
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                pendingSpace = builder.Length > 0;
                continue;
            }
            if (pendingSpace && builder.Length < limit - 3)
            {
                builder.Append(' ');
            }
            pendingSpace = false;
            if (builder.Length + 1 > limit - 3)
            {
                builder.Append("...");
                break;
            }
            builder.Append(character);
        }
        return builder.ToString();
    }
}
