using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost.FailingFixture;

[ReSymbolPlugin("dev.resymbol.test.failing-managed")]
public sealed class FailingPlugin : IReSymbolPlugin
{
    private IPluginHost? host;

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.failing-managed",
        "Failing managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        []);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        this.host = host;
        return ValueTask.CompletedTask;
    }

    public ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        host?.Log(PluginLogLevel.Warning, "this event must be rolled back");
        throw new InvalidOperationException("intentional fixture exception");
    }

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
