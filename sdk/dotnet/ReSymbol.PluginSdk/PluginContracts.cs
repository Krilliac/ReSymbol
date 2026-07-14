using System.Text.Json;

namespace ReSymbol.PluginSdk;

/// <summary>Version of the managed plugin contract implemented by this SDK.</summary>
public static class PluginApi
{
    public const int Major = 0;
    public const int Minor = 1;
    public const int Patch = 0;
    public static Version Version { get; } = new(Major, Minor, Patch);
}

/// <summary>
/// Isolation a plugin can support. Managed plugins run in ReSymbol's dedicated
/// plugin-host process unless the user explicitly trusts an in-process plugin.
/// A plugin declaration alone never grants that trust.
/// </summary>
public enum PluginIsolationRequirement
{
    OutOfProcess = 1,
    TrustedInProcessAllowed = 2,
}

public enum PluginLogLevel
{
    Trace,
    Debug,
    Information,
    Warning,
    Error,
}

public enum PluginHealthState
{
    Healthy,
    Degraded,
    Unhealthy,
}

/// <summary>Identifies the class instantiated for a managed plugin.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ReSymbolPluginAttribute(string id) : Attribute
{
    public string Id { get; } = id;
}

public sealed record PluginMetadata(
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> RequestedPermissions,
    PluginIsolationRequirement Isolation = PluginIsolationRequirement.OutOfProcess);

public sealed record PluginLimits(
    long MaxMemoryBytes,
    long MaxMessageBytes,
    TimeSpan AnalyzeTimeout);

public sealed record PluginInitialization(
    string SessionId,
    Version HostApiVersion,
    IReadOnlyList<string> GrantedPermissions,
    PluginLimits Limits,
    JsonElement Options);

public sealed record BinaryIdentity(
    string Sha256,
    string Format,
    string Architecture,
    ulong ImageSize);

public sealed record AnalysisRequest(
    string RequestId,
    BinaryIdentity Binary,
    string Phase,
    JsonElement Options);

/// <summary>
/// An evidence-backed proposal. The core validates claims and owns canonical
/// symbol state; plugins never mutate the symbol graph directly.
/// </summary>
public sealed record SymbolClaim(
    JsonElement Subject,
    JsonElement Claim,
    double Confidence,
    IReadOnlyList<ClaimEvidence> Evidence);

public sealed record ClaimEvidence(
    string Kind,
    string Description,
    JsonElement? Data = null);

public sealed record PluginHealth(
    PluginHealthState State,
    string? Message = null,
    IReadOnlyDictionary<string, string>? Details = null);
