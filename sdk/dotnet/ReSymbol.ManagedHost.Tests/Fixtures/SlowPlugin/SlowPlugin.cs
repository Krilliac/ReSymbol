using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost.SlowFixture;

[ReSymbolPlugin("dev.resymbol.test.slow-managed")]
public sealed class SlowPlugin : IReSymbolPlugin
{
    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.slow-managed",
        "Slow managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        []);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

    public async ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default) =>
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
