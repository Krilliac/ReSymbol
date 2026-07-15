namespace ReSymbol.PluginSdk;

/// <summary>
/// Capability-limited services exposed by the managed plugin host. Access is
/// checked against the permissions granted in <see cref="PluginInitialization"/>.
/// </summary>
public interface IPluginHost
{
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
    PluginMetadata Metadata { get; }

    /// <summary>
    /// Called once in the isolated managed host before any analysis request.
    /// </summary>
    ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default);

    ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default);

    /// <summary>Called at most once before the host terminates the plugin.</summary>
    ValueTask ShutdownAsync(CancellationToken cancellationToken = default);
}
