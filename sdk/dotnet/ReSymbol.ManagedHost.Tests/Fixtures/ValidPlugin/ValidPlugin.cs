using System.Text.Json;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost.ValidFixture;

[ReSymbolPlugin("dev.resymbol.test.valid-managed")]
public sealed class ValidPlugin : IReSymbolPlugin
{
    private IPluginHost? host;

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.test.valid-managed",
        "Valid managed host fixture",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read", "claims.submit"]);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        this.host = host;
        return ValueTask.CompletedTask;
    }

    public async ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        var bytes = new byte[2];
        var read = await (host ?? throw new InvalidOperationException("not initialized"))
            .ReadBinaryAsync(0, bytes, cancellationToken);
        if (read != 2 || bytes[0] != 'M' || bytes[1] != 'Z')
        {
            throw new InvalidOperationException("fixture did not receive exact PE header bytes");
        }
        host.Log(PluginLogLevel.Information, "verified exact PE header");
        var subject = JsonSerializer.SerializeToElement(new
        {
            kind = "global",
            binary = request.Binary.Sha256,
            rva = 0UL,
            size = 2UL,
        });
        await host.SubmitClaimAsync(new SymbolClaim(
            subject,
            ClaimAssertions.StringLiteral(StringEncoding.Ascii, "MZ"),
            1.0,
            [new ClaimEvidence("string-literal", "verified DOS signature")]),
            cancellationToken);
    }

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
