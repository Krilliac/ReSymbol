using System.Text.Json;
using ReSymbol.PluginSdk;

namespace Example.ManagedMatcher;

[ReSymbolPlugin("dev.resymbol.example.managed-matcher")]
public sealed class ManagedMatcherPlugin : IReSymbolPlugin
{
    private IPluginHost? host;

    public PluginMetadata Metadata { get; } = new(
        "dev.resymbol.example.managed-matcher",
        "Example Managed Function Matcher",
        "0.1.0",
        ["matcher.functions"],
        ["binary.read", "symbols.read", "claims.submit"]);

    public ValueTask InitializeAsync(
        IPluginHost host,
        PluginInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        this.host = host ?? throw new ArgumentNullException(nameof(host));
        return ValueTask.CompletedTask;
    }

    public ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        host?.Log(
            PluginLogLevel.Debug,
            "Example initialized; use ClaimContractExample after validating binary evidence.");
        return ValueTask.CompletedTask;
    }

    public ValueTask<PluginHealth> CheckHealthAsync(
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new PluginHealth(PluginHealthState.Healthy));

    public ValueTask ShutdownAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public static class ClaimContractExample
{
    public static SymbolClaim AsciiString(
        string binarySha256,
        ulong stringRva,
        string value,
        double confidence)
    {
        var assertion = ClaimAssertions.StringLiteral(StringEncoding.Ascii, value);
        var subject = JsonSerializer.SerializeToElement(new
        {
            kind = "global",
            binary = binarySha256,
            rva = stringRva,
            size = checked((ulong)value.Length + 1),
        });
        return new SymbolClaim(
            subject,
            assertion,
            confidence,
            [new ClaimEvidence("string-literal", "decoded printable ASCII plus NUL")]);
    }

    public static SymbolClaim DataReference(
        string binarySha256,
        ulong functionRva,
        ulong instructionRva,
        byte instructionSize,
        ulong targetRva,
        double confidence)
    {
        var assertion = ClaimAssertions.DataReference(
            instructionRva,
            instructionSize,
            targetRva);
        var subject = JsonSerializer.SerializeToElement(new
        {
            kind = "function",
            binary = binarySha256,
            rva = functionRva,
        });
        return new SymbolClaim(
            subject,
            assertion,
            confidence,
            [new ClaimEvidence("data-flow", "validated instruction operand")]);
    }
}
