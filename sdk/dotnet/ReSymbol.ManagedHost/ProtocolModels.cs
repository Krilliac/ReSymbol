using System.Text.Json;
using System.Text.Json.Serialization;

namespace ReSymbol.ManagedHost;

internal static class ProtocolConstants
{
    internal const string ManagedHost = "resymbol.managed-host";
    internal const string PluginWire = "resymbol.plugin-wire";
    internal const int Major = 1;
    internal const int Minor = 0;
    internal const int MaxBootstrapBytes = 256 * 1024;
    internal const int MaxInitialWireBytes = 64 * 1024 * 1024;
    internal const int HardMaxStdoutBytes = 8 * 1024 * 1024;
    internal const int HardMaxBinaryBytes = 1024 * 1024 * 1024;
    internal const int MaxBinaryReadCallBytes = 1024 * 1024;
    internal const long MaxAdvertisedMemoryBytes = 64L * 1024 * 1024 * 1024;
    internal const ulong MaxTimeoutMilliseconds = 24UL * 60 * 60 * 1000;
    internal const int MaxIdentifierBytes = 128;
    internal const int MaxPermissions = 256;
    internal const int MaxAssemblyEntries = 512;

    internal static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = null,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = 64,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}

internal sealed record ProtocolVersion(int Major, int Minor);

internal sealed record OutputLimits(int MaxMessages, int MaxStdoutBytes);

internal sealed record ServiceLimits(long MaxBinaryReadBytes);

internal sealed record ExpectedAssembly(string Path, string Sha256);

internal sealed record ExpectedPlugin(
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> RequestedPermissions);

internal sealed record BinaryIdentityModel(
    string Id,
    ulong Size,
    string Format,
    string Architecture,
    ulong ImageBase = 0)
{
    internal string FormatName => Format;
}

internal sealed record PeImageSection(
    uint VirtualAddress,
    uint VirtualSize,
    uint RawDataOffset,
    uint RawDataSize);

internal sealed record PeImageMap(
    uint SizeOfHeaders,
    uint SizeOfImage,
    IReadOnlyList<PeImageSection> Sections);

internal sealed record ManagedHostBootstrap(
    string Protocol,
    ProtocolVersion Version,
    string ExpectedArtifactSha256,
    string EntryAssembly,
    ExpectedPlugin ExpectedPlugin,
    IReadOnlyList<ExpectedAssembly> Assemblies,
    OutputLimits OutputLimits,
    ServiceLimits ServiceLimits,
    BinaryIdentityModel Binary,
    PeImageMap Image,
    [property: JsonPropertyName("deadline_unix_ms")]
    long? DeadlineUnixMilliseconds = null);

internal sealed record WireLimits(
    int MaxMessageBytes,
    ulong MaxMemoryBytes,
    [property: JsonPropertyName("request_timeout_ms")]
    ulong RequestTimeoutMilliseconds);

internal sealed record WireIsolation(string Mode, bool Required);

internal sealed record HostHello(
    string Protocol,
    ProtocolVersion Version,
    string Kind,
    string SessionId,
    string PluginId,
    IReadOnlyList<string> GrantedPermissions,
    WireLimits Limits,
    WireIsolation Isolation);

internal sealed record HostRequest(
    string Protocol,
    ProtocolVersion Version,
    string Kind,
    string Direction,
    string Id,
    string Method,
    JsonElement Payload);

internal sealed record HostInput(
    ManagedHostBootstrap Bootstrap,
    HostHello Hello,
    HostRequest Request);

internal sealed record PluginDescriptorModel(
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> RequestedPermissions);

// The complete event envelope is serialized exactly once at callback time.
// The backing array is never exposed as writable state, so later plugin
// mutation cannot change either validation or byte accounting.
internal sealed class BufferedEvent
{
    private readonly byte[] encodedLine;

    internal BufferedEvent(string method, byte[] encodedLine)
    {
        Method = method ?? throw new ArgumentNullException(nameof(method));
        this.encodedLine = encodedLine ??
            throw new ArgumentNullException(nameof(encodedLine));
    }

    internal string Method { get; }

    internal int EncodedLineLength => encodedLine.Length;

    internal ReadOnlySpan<byte> EncodedLine => encodedLine;
}

internal sealed record PluginRejection(string Code, string Message);

internal sealed record ManagedExecution(
    PluginDescriptorModel Descriptor,
    IReadOnlyList<BufferedEvent> Events,
    PluginRejection? Rejection);
