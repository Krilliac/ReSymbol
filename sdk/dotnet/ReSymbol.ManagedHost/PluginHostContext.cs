using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal enum PluginHostPhase
{
    Initialization,
    HealthCheck,
    Analysis,
    Shutdown,
    Disposal,
}

// Every invocation receives an execution-context lease. Structured child work
// inherits that lease, but it becomes unusable before the host enters the next
// phase. binary.read is available only during initialization/analysis and
// claims.submit only during analysis; all callbacks are closed after Finish.
internal sealed class PluginHostContext : IPluginHost
{
    private readonly ExactBinaryImage binary;
    private readonly HashSet<string> grants;
    private readonly string binarySha256;
    private readonly int maxEvents;
    private readonly int maxMessageBytes;
    private readonly int maxEventBytes;
    private readonly long maxBinaryReadBytes;
    private readonly object gate = new();
    private readonly AsyncLocal<PhaseLease?> callerPhase = new();
    private readonly List<BufferedEvent> events = [];
    private int eventBytes;
    private long binaryReadBytes;
    private bool accepting = true;
    private PhaseLease? activePhase;
    private LifecycleState lifecycle = LifecycleState.Created;

    internal PluginHostContext(
        ExactBinaryImage binary,
        HostInput input)
    {
        this.binary = binary;
        grants = new HashSet<string>(input.Hello.GrantedPermissions, StringComparer.Ordinal);
        binarySha256 = input.Bootstrap.Binary.Id;
        maxEvents = input.Bootstrap.OutputLimits.MaxMessages - 2;
        maxMessageBytes = input.Hello.Limits.MaxMessageBytes;
        maxEventBytes = WireOutput.CommittedEventByteBudget(
            input.Bootstrap.ExpectedPlugin,
            input.Request.Id,
            maxMessageBytes,
            input.Bootstrap.OutputLimits.MaxStdoutBytes);
        maxBinaryReadBytes = input.Bootstrap.ServiceLimits.MaxBinaryReadBytes;
    }

    public void Log(PluginLogLevel level, string message)
    {
        lock (gate)
        {
            RequireActiveCaller("log");
            if (message is null)
            {
                throw new HostInvalidArgumentException(
                    "managed plugin log message is null");
            }
            var wireLevel = level switch
            {
                PluginLogLevel.Trace => "trace",
                PluginLogLevel.Debug => "debug",
                PluginLogLevel.Information => "info",
                PluginLogLevel.Warning => "warn",
                PluginLogLevel.Error => "error",
                _ => throw new HostInvalidArgumentException(
                    "managed plugin used an invalid log level"),
            };
            BufferLocked("log", new { level = wireLevel, message });
        }
    }

    public ValueTask<int> ReadBinaryAsync(
        ulong rva,
        Memory<byte> destination,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            RequireActiveCaller(
                "binary.read",
                PluginHostPhase.Initialization,
                PluginHostPhase.Analysis);
            RequirePermission("binary.read");
            if (destination.Length > ProtocolConstants.MaxBinaryReadCallBytes)
            {
                throw new HostResourceLimitException(
                    "binary.read request exceeds the per-call limit");
            }
            ChargeBinaryReadLocked(destination.Length);
            try
            {
                return binary.ReadRvaAsync(rva, destination, cancellationToken);
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new HostInvalidArgumentException(
                    "binary.read RVA lies outside the exact image",
                    exception);
            }
        }
    }

    public ValueTask SubmitClaimAsync(
        SymbolClaim claim,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            RequireActiveCaller("claims.submit", PluginHostPhase.Analysis);
            RequirePermission("claims.submit");
            if (claim is null)
            {
                throw new HostInvalidArgumentException(
                    "managed plugin claim is null");
            }
            try
            {
                ClaimValidator.Validate(claim, binarySha256);
            }
            catch (HostException exception)
            {
                throw new HostInvalidArgumentException(
                    exception.Message,
                    exception);
            }
            catch (InvalidOperationException exception)
            {
                throw new HostInvalidArgumentException(
                    "managed plugin claim contains unavailable JSON state",
                    exception);
            }
            BufferLocked("claim", claim);
        }
        return ValueTask.CompletedTask;
    }

    internal IDisposable EnterPhase(PluginHostPhase phase)
    {
        lock (gate)
        {
            if (!accepting || activePhase is not null)
            {
                throw new HostException("managed plugin lifecycle phase overlap detected");
            }
            ValidateTransition(phase);
            var lease = new PhaseLease(this, phase);
            activePhase = lease;
            callerPhase.Value = lease;
            return lease;
        }
    }

    internal IReadOnlyList<BufferedEvent> Finish(bool commit)
    {
        lock (gate)
        {
            accepting = false;
            if (activePhase is not null)
            {
                activePhase.IsOpen = false;
                activePhase = null;
            }
            lifecycle = LifecycleState.Finished;
            if (!commit)
            {
                events.Clear();
                eventBytes = 0;
            }
            return events.ToArray();
        }
    }

    private void BufferLocked(string method, object payload)
    {
        if (events.Count >= maxEvents)
        {
            throw new HostResourceLimitException(
                "managed plugin output message-count limit exceeded");
        }
        var pluginEvent = WireOutput.EncodeEvent(method, payload, maxMessageBytes);
        var framedLength = checked(pluginEvent.EncodedLineLength + 1);
        if (framedLength > maxEventBytes - eventBytes)
        {
            throw new HostResourceLimitException(
                "managed plugin aggregate output limit exceeded");
        }
        events.Add(pluginEvent);
        eventBytes += framedLength;
    }

    private void RequirePermission(string permission)
    {
        if (!grants.Contains(permission))
        {
            throw new HostPermissionDeniedException(
                $"managed plugin was not granted {permission}");
        }
    }

    private void ChargeBinaryReadLocked(int count)
    {
        var next = checked(binaryReadBytes + count);
        if (next > maxBinaryReadBytes)
        {
            throw new HostResourceLimitException(
                "managed plugin exceeded its binary.read byte budget");
        }
        binaryReadBytes = next;
    }

    private void RequireActiveCaller(
        string service,
        params PluginHostPhase[] allowedPhases)
    {
        var lease = callerPhase.Value;
        if (!accepting || lease is null || !lease.IsOpen ||
            !ReferenceEquals(activePhase, lease) ||
            (allowedPhases.Length > 0 && !allowedPhases.Contains(lease.Phase)))
        {
            throw new HostServiceUnavailableException(
                $"managed plugin {service} service is unavailable in this lifecycle phase");
        }
    }

    private void ValidateTransition(PluginHostPhase phase)
    {
        var valid = phase switch
        {
            PluginHostPhase.Initialization => lifecycle == LifecycleState.Created,
            PluginHostPhase.HealthCheck => lifecycle == LifecycleState.Initialized,
            PluginHostPhase.Analysis => lifecycle == LifecycleState.HealthChecked,
            PluginHostPhase.Shutdown => lifecycle is LifecycleState.Initialized or
                LifecycleState.HealthChecked or LifecycleState.Analyzed,
            PluginHostPhase.Disposal => lifecycle == LifecycleState.ShutDown,
            _ => false,
        };
        if (!valid)
        {
            throw new HostException("managed plugin lifecycle transition is invalid");
        }
    }

    private void LeavePhase(PhaseLease lease)
    {
        lock (gate)
        {
            if (lease.IsOpen && ReferenceEquals(activePhase, lease))
            {
                lease.IsOpen = false;
                activePhase = null;
                lifecycle = lease.Phase switch
                {
                    PluginHostPhase.Initialization => LifecycleState.Initialized,
                    PluginHostPhase.HealthCheck => LifecycleState.HealthChecked,
                    PluginHostPhase.Analysis => LifecycleState.Analyzed,
                    PluginHostPhase.Shutdown => LifecycleState.ShutDown,
                    PluginHostPhase.Disposal => LifecycleState.Disposed,
                    _ => throw new HostException("managed plugin lifecycle phase is invalid"),
                };
            }
        }
        if (ReferenceEquals(callerPhase.Value, lease))
        {
            callerPhase.Value = null;
        }
    }

    private enum LifecycleState
    {
        Created,
        Initialized,
        HealthChecked,
        Analyzed,
        ShutDown,
        Disposed,
        Finished,
    }

    private sealed class PhaseLease(
        PluginHostContext owner,
        PluginHostPhase phase) : IDisposable
    {
        internal PluginHostPhase Phase { get; } = phase;
        internal bool IsOpen { get; set; } = true;

        public void Dispose() => owner.LeavePhase(this);
    }
}
