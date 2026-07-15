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

    public async ValueTask AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.BaseAnalysis is not { ValueKind: JsonValueKind.Object })
        {
            throw new InvalidOperationException(
                "The managed example requires its granted symbols.read base analysis.");
        }
        var activeHost = host ?? throw new InvalidOperationException(
            "The managed example was analyzed before initialization.");
        var signature = new byte[2];
        var bytesRead = await activeHost.ReadBinaryAsync(
            0,
            signature,
            cancellationToken);
        if (bytesRead != signature.Length || signature[0] != (byte)'M' ||
            signature[1] != (byte)'Z')
        {
            activeHost.Log(
                PluginLogLevel.Warning,
                "Example found no exact DOS MZ signature; no claim was submitted.");
            return;
        }

        var subject = JsonSerializer.SerializeToElement(new
        {
            kind = "global",
            binary = request.Binary.Sha256,
            rva = 0UL,
            size = 2UL,
        });
        var assertion = JsonSerializer.SerializeToElement(new
        {
            kind = "comment",
            text = "Managed example verified the DOS MZ signature via binary.read.",
        });
        await activeHost.SubmitClaimAsync(
            new SymbolClaim(
                subject,
                assertion,
                1.0,
                [new ClaimEvidence(
                    "binary-read",
                    "exact image bytes at RVA 0 were 4d 5a")]),
            cancellationToken);
        activeHost.Log(
            PluginLogLevel.Debug,
            "Example received base analysis and submitted one exact MZ evidence claim.");
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
