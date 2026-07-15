namespace ReSymbol.PluginSdk;

/// <summary>
/// Capability-limited services exposed by the managed plugin host. Access is
/// checked against the permissions granted in <see cref="PluginInitialization"/>.
/// </summary>
public interface IPluginHost
{
    /// <summary>Emits a transactionally buffered diagnostic for the current plugin run.</summary>
    /// <param name="level">Severity assigned to the diagnostic.</param>
    /// <param name="message">UTF-16 diagnostic text to encode as bounded UTF-8 output.</param>
    void Log(PluginLogLevel level, string message);

    /// <summary>
    /// Reads from the current image by RVA. This avoids granting a plugin direct
    /// filesystem access merely to inspect the analyzed binary.
    /// </summary>
    ValueTask<int> ReadBinaryAsync(
        ulong rva,
        Memory<byte> destination,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Proposes a claim for validation by the ReSymbol core. Use
    /// <see cref="ClaimAssertions"/> for canonical string-literal and
    /// data-reference assertion JSON.
    /// </summary>
    ValueTask SubmitClaimAsync(
        SymbolClaim claim,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Entry contract for a managed plugin. Implementations must have a public
/// parameterless constructor and carry <see cref="ReSymbolPluginAttribute"/>.
/// A plugin assembly must expose exactly one attributed implementation.
/// </summary>
public interface IReSymbolPlugin : IAsyncDisposable
{
    /// <summary>Gets immutable identity, capability, permission, and isolation metadata.</summary>
    PluginMetadata Metadata { get; }

    /// <summary>
    /// Called once in the isolated managed host before any analysis request.
    /// </summary>
    ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default);

    /// <summary>Analyzes the exact binary bound to the current request.</summary>
    /// <param name="request">Host-owned request and exact binary identity.</param>
    /// <param name="cancellationToken">Token cancelled at the execution deadline.</param>
    ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Reports whether the initialized plugin is ready to analyze.</summary>
    /// <param name="cancellationToken">Token cancelled at the execution deadline.</param>
    /// <returns>The plugin's current health state and bounded optional details.</returns>
    ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default);

    /// <summary>Called at most once before the host terminates the plugin.</summary>
    ValueTask ShutdownAsync(CancellationToken cancellationToken = default);
}
