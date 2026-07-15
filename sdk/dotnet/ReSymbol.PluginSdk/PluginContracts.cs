using System.Text.Json;
using System.Text.Json.Serialization;

namespace ReSymbol.PluginSdk;

/// <summary>Version of the managed plugin contract implemented by this SDK.</summary>
public static class PluginApi
{
    /// <summary>Major managed SDK contract version.</summary>
    public const int Major = 0;
    /// <summary>Minor managed SDK contract version.</summary>
    public const int Minor = 1;
    /// <summary>Patch managed SDK contract version.</summary>
    public const int Patch = 0;
    /// <summary>Gets the complete managed SDK contract version.</summary>
    public static Version Version { get; } = new(Major, Minor, Patch);
}

/// <summary>
/// Isolation a plugin can support. Managed plugins run in ReSymbol's dedicated
/// plugin-host process unless the user explicitly trusts an in-process plugin.
/// A plugin declaration alone never grants that trust.
/// </summary>
public enum PluginIsolationRequirement
{
    /// <summary>The plugin requires a dedicated helper process.</summary>
    OutOfProcess = 1,
    /// <summary>
    /// The plugin can tolerate a separately designed trusted in-process host.
    /// The current ReSymbol host still executes it out of process.
    /// </summary>
    TrustedInProcessAllowed = 2,
}

/// <summary>Severity for one transactionally buffered plugin diagnostic.</summary>
public enum PluginLogLevel
{
    /// <summary>Fine-grained execution tracing.</summary>
    Trace,
    /// <summary>Developer-oriented diagnostic information.</summary>
    Debug,
    /// <summary>Normal informational status.</summary>
    Information,
    /// <summary>A recoverable or suspicious condition.</summary>
    Warning,
    /// <summary>A plugin-reported error condition.</summary>
    Error,
}

/// <summary>Health returned after managed plugin initialization.</summary>
public enum PluginHealthState
{
    /// <summary>The plugin is ready to analyze.</summary>
    Healthy,
    /// <summary>The plugin is usable with a reported limitation.</summary>
    Degraded,
    /// <summary>The plugin must not analyze the request.</summary>
    Unhealthy,
}

/// <summary>Encoding used to decode a recovered string literal.</summary>
[JsonConverter(typeof(StringEncodingJsonConverter))]
public enum StringEncoding
{
    /// <summary>Printable seven-bit ASCII with a one-byte terminator.</summary>
    Ascii,
    /// <summary>Little-endian UTF-16 with a two-byte terminator.</summary>
    Utf16Le,
}

/// <summary>Reads and writes the exact protocol-1 string-encoding names.</summary>
public sealed class StringEncodingJsonConverter : JsonConverter<StringEncoding>
{
    /// <inheritdoc />
    public override StringEncoding Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("A string encoding must be a protocol string.");
        }

        return reader.GetString() switch
        {
            "ascii" => StringEncoding.Ascii,
            "utf-16-le" => StringEncoding.Utf16Le,
            var value => throw new JsonException($"Unknown string encoding '{value}'."),
        };
    }

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer,
        StringEncoding value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(value switch
        {
            StringEncoding.Ascii => "ascii",
            StringEncoding.Utf16Le => "utf-16-le",
            _ => throw new JsonException($"Unknown string encoding value {value}."),
        });
    }
}

/// <summary>Canonical protocol-1 symbol-assertion discriminators.</summary>
public static class ClaimAssertionKinds
{
    /// <summary>Discriminator for an exact recovered string literal.</summary>
    public const string StringLiteral = "string-literal";
    /// <summary>Discriminator for an instruction-to-data reference.</summary>
    public const string DataReference = "data-reference";
}

/// <summary>Canonical payload for a <c>string-literal</c> assertion.</summary>
public sealed record StringLiteralAssertion
{
    /// <summary>Creates a validated canonical string-literal assertion.</summary>
    /// <param name="encoding">Exact encoding used by the binary.</param>
    /// <param name="value">Decoded, nonempty literal value without its terminator.</param>
    [JsonConstructor]
    public StringLiteralAssertion(StringEncoding encoding, string value)
    {
        ClaimAssertions.ValidateStringLiteral(encoding, value);
        Encoding = encoding;
        Value = value;
    }

    /// <summary>Gets the canonical assertion discriminator.</summary>
    [JsonPropertyName("kind")]
    public string Kind => ClaimAssertionKinds.StringLiteral;

    /// <summary>Gets the exact source encoding.</summary>
    [JsonPropertyName("encoding")]
    public StringEncoding Encoding { get; }

    /// <summary>Gets the decoded literal value without its terminator.</summary>
    [JsonPropertyName("value")]
    public string Value { get; }
}

/// <summary>Canonical payload for a <c>data-reference</c> assertion.</summary>
public sealed record DataReferenceAssertion
{
    /// <summary>Creates a validated canonical data-reference assertion.</summary>
    /// <param name="instructionRva">RVA of the referencing instruction.</param>
    /// <param name="instructionSize">Nonzero encoded instruction size in bytes.</param>
    /// <param name="targetRva">Resolved target RVA.</param>
    [JsonConstructor]
    public DataReferenceAssertion(
        ulong instructionRva,
        byte instructionSize,
        ulong targetRva)
    {
        if (instructionSize == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(instructionSize),
                "Instruction size must be nonzero.");
        }

        InstructionRva = instructionRva;
        InstructionSize = instructionSize;
        TargetRva = targetRva;
    }

    /// <summary>Gets the canonical assertion discriminator.</summary>
    [JsonPropertyName("kind")]
    public string Kind => ClaimAssertionKinds.DataReference;

    /// <summary>Gets the RVA of the referencing instruction.</summary>
    [JsonPropertyName("instruction_rva")]
    public ulong InstructionRva { get; }

    /// <summary>Gets the nonzero encoded instruction size.</summary>
    [JsonPropertyName("instruction_size")]
    public byte InstructionSize { get; }

    /// <summary>Gets the resolved target RVA.</summary>
    [JsonPropertyName("target_rva")]
    public ulong TargetRva { get; }
}

/// <summary>
/// Creates validated canonical JSON assertions accepted by <see cref="SymbolClaim"/>.
/// </summary>
public static class ClaimAssertions
{
    /// <summary>Creates canonical JSON for an exact recovered string literal.</summary>
    /// <param name="encoding">Exact encoding used by the binary.</param>
    /// <param name="value">Decoded value without its terminator.</param>
    /// <returns>A detached JSON element accepted by <see cref="SymbolClaim"/>.</returns>
    public static JsonElement StringLiteral(StringEncoding encoding, string value) =>
        JsonSerializer.SerializeToElement(new StringLiteralAssertion(encoding, value));

    /// <summary>Creates canonical JSON for one instruction-to-data reference.</summary>
    /// <param name="instructionRva">RVA of the referencing instruction.</param>
    /// <param name="instructionSize">Nonzero encoded instruction size.</param>
    /// <param name="targetRva">Resolved target RVA.</param>
    /// <returns>A detached JSON element accepted by <see cref="SymbolClaim"/>.</returns>
    public static JsonElement DataReference(
        ulong instructionRva,
        byte instructionSize,
        ulong targetRva) =>
        JsonSerializer.SerializeToElement(
            new DataReferenceAssertion(instructionRva, instructionSize, targetRva));

    internal static void ValidateStringLiteral(StringEncoding encoding, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "String literal text must not be empty or whitespace-only.",
                nameof(value));
        }

        if (encoding == StringEncoding.Ascii)
        {
            if (value.Any(character => character is < ' ' or > '~'))
            {
                throw new ArgumentException(
                    "ASCII string literals may contain only bytes 0x20 through 0x7e.",
                    nameof(value));
            }
            return;
        }

        if (encoding != StringEncoding.Utf16Le)
        {
            throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unknown encoding.");
        }

        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsControl(character))
            {
                throw new ArgumentException(
                    "UTF-16LE string literals must not contain control characters.",
                    nameof(value));
            }
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    throw new ArgumentException(
                        "UTF-16LE string literals must contain valid surrogate pairs.",
                        nameof(value));
                }
                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                throw new ArgumentException(
                    "UTF-16LE string literals must contain valid surrogate pairs.",
                    nameof(value));
            }
        }
    }
}

/// <summary>Identifies the class instantiated for a managed plugin.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ReSymbolPluginAttribute(string id) : Attribute
{
    /// <summary>Gets the manifest-compatible plugin identifier.</summary>
    public string Id { get; } = id;
}

/// <summary>Identity and requested host surface declared by a managed plugin.</summary>
public sealed record PluginMetadata
{
    /// <summary>Creates immutable plugin metadata.</summary>
    /// <param name="Id">Manifest-compatible plugin identifier.</param>
    /// <param name="Name">Human-readable plugin name.</param>
    /// <param name="Version">Plugin version matching its manifest.</param>
    /// <param name="Capabilities">Capabilities provided by the plugin.</param>
    /// <param name="RequestedPermissions">Host operations requested by the plugin.</param>
    /// <param name="Isolation">Strongest isolation requirement supported by the plugin.</param>
    public PluginMetadata(
        string Id,
        string Name,
        string Version,
        IReadOnlyList<string> Capabilities,
        IReadOnlyList<string> RequestedPermissions,
        PluginIsolationRequirement Isolation = PluginIsolationRequirement.OutOfProcess)
    {
        this.Id = Id;
        this.Name = Name;
        this.Version = Version;
        this.Capabilities = Capabilities;
        this.RequestedPermissions = RequestedPermissions;
        this.Isolation = Isolation;
    }

    /// <summary>Gets the manifest-compatible plugin identifier.</summary>
    public string Id { get; init; }

    /// <summary>Gets the human-readable plugin name.</summary>
    public string Name { get; init; }

    /// <summary>Gets the plugin version matching its manifest.</summary>
    public string Version { get; init; }

    /// <summary>Gets the capabilities provided by the plugin.</summary>
    public IReadOnlyList<string> Capabilities { get; init; }

    /// <summary>Gets the host operations requested by the plugin.</summary>
    public IReadOnlyList<string> RequestedPermissions { get; init; }

    /// <summary>Gets the plugin's isolation requirement.</summary>
    public PluginIsolationRequirement Isolation { get; init; }

    /// <summary>Deconstructs the metadata into its positional contract values.</summary>
    public void Deconstruct(
        out string Id,
        out string Name,
        out string Version,
        out IReadOnlyList<string> Capabilities,
        out IReadOnlyList<string> RequestedPermissions,
        out PluginIsolationRequirement Isolation)
    {
        Id = this.Id;
        Name = this.Name;
        Version = this.Version;
        Capabilities = this.Capabilities;
        RequestedPermissions = this.RequestedPermissions;
        Isolation = this.Isolation;
    }
}

/// <summary>Resource limits advertised to one managed plugin execution.</summary>
public sealed record PluginLimits
{
    /// <summary>Creates an advertised limit set.</summary>
    /// <param name="MaxMemoryBytes">Verified-snapshot byte budget.</param>
    /// <param name="MaxMessageBytes">Maximum encoded protocol-message size.</param>
    /// <param name="AnalyzeTimeout">Wall-clock analysis deadline.</param>
    public PluginLimits(long MaxMemoryBytes, long MaxMessageBytes, TimeSpan AnalyzeTimeout)
    {
        this.MaxMemoryBytes = MaxMemoryBytes;
        this.MaxMessageBytes = MaxMessageBytes;
        this.AnalyzeTimeout = AnalyzeTimeout;
    }

    /// <summary>
    /// Gets the verified-snapshot byte budget. This is not a CLR process-memory limit.
    /// </summary>
    public long MaxMemoryBytes { get; init; }

    /// <summary>Gets the maximum encoded protocol-message size.</summary>
    public long MaxMessageBytes { get; init; }

    /// <summary>Gets the wall-clock analysis deadline.</summary>
    public TimeSpan AnalyzeTimeout { get; init; }

    /// <summary>Deconstructs the advertised resource limits.</summary>
    public void Deconstruct(
        out long MaxMemoryBytes,
        out long MaxMessageBytes,
        out TimeSpan AnalyzeTimeout)
    {
        MaxMemoryBytes = this.MaxMemoryBytes;
        MaxMessageBytes = this.MaxMessageBytes;
        AnalyzeTimeout = this.AnalyzeTimeout;
    }
}

/// <summary>Host-owned context supplied once during plugin initialization.</summary>
public sealed record PluginInitialization
{
    /// <summary>Creates initialization context for one isolated run.</summary>
    /// <param name="SessionId">Stable identifier for the analysis session.</param>
    /// <param name="HostApiVersion">Managed contract version implemented by the host.</param>
    /// <param name="GrantedPermissions">Requested permissions granted for this run.</param>
    /// <param name="Limits">Resource limits advertised for this run.</param>
    /// <param name="Options">Detached host-owned plugin options.</param>
    public PluginInitialization(
        string SessionId,
        Version HostApiVersion,
        IReadOnlyList<string> GrantedPermissions,
        PluginLimits Limits,
        JsonElement Options)
    {
        this.SessionId = SessionId;
        this.HostApiVersion = HostApiVersion;
        this.GrantedPermissions = GrantedPermissions;
        this.Limits = Limits;
        this.Options = Options;
    }

    /// <summary>Gets the analysis-session identifier.</summary>
    public string SessionId { get; init; }

    /// <summary>Gets the managed contract version implemented by the host.</summary>
    public Version HostApiVersion { get; init; }

    /// <summary>Gets the requested permissions granted for this run.</summary>
    public IReadOnlyList<string> GrantedPermissions { get; init; }

    /// <summary>Gets the resource limits advertised for this run.</summary>
    public PluginLimits Limits { get; init; }

    /// <summary>Gets detached host-owned plugin options.</summary>
    public JsonElement Options { get; init; }

    /// <summary>Deconstructs the initialization context.</summary>
    public void Deconstruct(
        out string SessionId,
        out Version HostApiVersion,
        out IReadOnlyList<string> GrantedPermissions,
        out PluginLimits Limits,
        out JsonElement Options)
    {
        SessionId = this.SessionId;
        HostApiVersion = this.HostApiVersion;
        GrantedPermissions = this.GrantedPermissions;
        Limits = this.Limits;
        Options = this.Options;
    }
}

/// <summary>
/// Exact analyzed-file identity plus the loader-visible image bounds. FileSize
/// is the hashed on-disk byte length; VirtualImageSize is the mapped image size.
/// </summary>
public sealed record BinaryIdentity
{
    /// <summary>Creates an exact analyzed-file identity and image-bound record.</summary>
    /// <param name="Sha256">Lowercase SHA-256 of the exact source file.</param>
    /// <param name="Format">Canonical binary-format name.</param>
    /// <param name="Architecture">Canonical target-architecture name.</param>
    /// <param name="FileSize">Hashed on-disk file size.</param>
    /// <param name="ImageBase">Preferred image base.</param>
    /// <param name="VirtualImageSize">Loader-visible virtual image size.</param>
    public BinaryIdentity(
        string Sha256,
        string Format,
        string Architecture,
        ulong FileSize,
        ulong ImageBase,
        ulong VirtualImageSize)
    {
        this.Sha256 = Sha256;
        this.Format = Format;
        this.Architecture = Architecture;
        this.FileSize = FileSize;
        this.ImageBase = ImageBase;
        this.VirtualImageSize = VirtualImageSize;
    }

    /// <summary>Gets the SHA-256 of the exact source file.</summary>
    public string Sha256 { get; init; }

    /// <summary>Gets the canonical binary-format name.</summary>
    public string Format { get; init; }

    /// <summary>Gets the canonical target-architecture name.</summary>
    public string Architecture { get; init; }

    /// <summary>Gets the hashed on-disk file size.</summary>
    public ulong FileSize { get; init; }

    /// <summary>Gets the preferred image base.</summary>
    public ulong ImageBase { get; init; }

    /// <summary>Gets the loader-visible virtual image size.</summary>
    public ulong VirtualImageSize { get; init; }

    /// <summary>Deconstructs the exact binary identity and image bounds.</summary>
    public void Deconstruct(
        out string Sha256,
        out string Format,
        out string Architecture,
        out ulong FileSize,
        out ulong ImageBase,
        out ulong VirtualImageSize)
    {
        Sha256 = this.Sha256;
        Format = this.Format;
        Architecture = this.Architecture;
        FileSize = this.FileSize;
        ImageBase = this.ImageBase;
        VirtualImageSize = this.VirtualImageSize;
    }
}

/// <summary>One host-owned request to analyze an exact binary.</summary>
public sealed record AnalysisRequest
{
    /// <summary>Creates one managed analysis request.</summary>
    /// <param name="RequestId">Identifier correlated with the terminal response.</param>
    /// <param name="Binary">Exact analyzed-file identity.</param>
    /// <param name="Phase">Host-defined analysis phase name.</param>
    /// <param name="Options">Detached host-owned request options.</param>
    public AnalysisRequest(
        string RequestId,
        BinaryIdentity Binary,
        string Phase,
        JsonElement Options)
        : this(RequestId, Binary, Phase, Options, null)
    {
    }

    /// <summary>Creates one managed analysis request with optional base-analysis data.</summary>
    /// <param name="RequestId">Identifier correlated with the terminal response.</param>
    /// <param name="Binary">Exact analyzed-file identity.</param>
    /// <param name="Phase">Host-defined analysis phase name.</param>
    /// <param name="Options">Detached host-owned request options.</param>
    /// <param name="BaseAnalysis">
    /// Detached canonical base analysis, or null when symbols.read was not granted.
    /// </param>
    public AnalysisRequest(
        string RequestId,
        BinaryIdentity Binary,
        string Phase,
        JsonElement Options,
        JsonElement? BaseAnalysis)
    {
        this.RequestId = RequestId;
        this.Binary = Binary;
        this.Phase = Phase;
        this.Options = Options;
        this.BaseAnalysis = BaseAnalysis;
    }

    /// <summary>Gets the identifier correlated with the terminal response.</summary>
    public string RequestId { get; init; }

    /// <summary>Gets the exact analyzed-file identity.</summary>
    public BinaryIdentity Binary { get; init; }

    /// <summary>Gets the host-defined analysis phase name.</summary>
    public string Phase { get; init; }

    /// <summary>Gets detached host-owned request options.</summary>
    public JsonElement Options { get; init; }

    /// <summary>
    /// Gets detached canonical base analysis when symbols.read is granted; otherwise null.
    /// </summary>
    public JsonElement? BaseAnalysis { get; init; }

    /// <summary>Deconstructs the analysis request.</summary>
    public void Deconstruct(
        out string RequestId,
        out BinaryIdentity Binary,
        out string Phase,
        out JsonElement Options)
    {
        RequestId = this.RequestId;
        Binary = this.Binary;
        Phase = this.Phase;
        Options = this.Options;
    }
}

/// <summary>
/// An evidence-backed proposal. The core validates claims and owns canonical
/// symbol state; plugins never mutate the symbol graph directly.
/// </summary>
public sealed record SymbolClaim
{
    /// <summary>Creates one evidence-backed symbol claim.</summary>
    /// <param name="Subject">Canonical JSON identity of the claimed entity.</param>
    /// <param name="Claim">Canonical tagged assertion JSON.</param>
    /// <param name="Confidence">Finite confidence in the inclusive range zero through one.</param>
    /// <param name="Evidence">Nonempty evidence supporting the assertion.</param>
    public SymbolClaim(
        JsonElement Subject,
        JsonElement Claim,
        double Confidence,
        IReadOnlyList<ClaimEvidence> Evidence)
    {
        this.Subject = Subject;
        this.Claim = Claim;
        this.Confidence = Confidence;
        this.Evidence = Evidence;
    }

    /// <summary>Gets canonical JSON identifying the claimed entity.</summary>
    public JsonElement Subject { get; init; }

    /// <summary>Gets the canonical tagged assertion JSON.</summary>
    public JsonElement Claim { get; init; }

    /// <summary>Gets the confidence in the inclusive range zero through one.</summary>
    public double Confidence { get; init; }

    /// <summary>Gets the evidence supporting the assertion.</summary>
    public IReadOnlyList<ClaimEvidence> Evidence { get; init; }

    /// <summary>Deconstructs the evidence-backed symbol claim.</summary>
    public void Deconstruct(
        out JsonElement Subject,
        out JsonElement Claim,
        out double Confidence,
        out IReadOnlyList<ClaimEvidence> Evidence)
    {
        Subject = this.Subject;
        Claim = this.Claim;
        Confidence = this.Confidence;
        Evidence = this.Evidence;
    }
}

/// <summary>One bounded evidence item supporting a symbol claim.</summary>
public sealed record ClaimEvidence
{
    /// <summary>Creates one evidence item.</summary>
    /// <param name="Kind">Canonical evidence-source category.</param>
    /// <param name="Description">Human-readable evidence summary.</param>
    /// <param name="Data">Optional structured evidence details.</param>
    public ClaimEvidence(string Kind, string Description, JsonElement? Data = null)
    {
        this.Kind = Kind;
        this.Description = Description;
        this.Data = Data;
    }

    /// <summary>Gets the canonical evidence-source category.</summary>
    public string Kind { get; init; }

    /// <summary>Gets the human-readable evidence summary.</summary>
    public string Description { get; init; }

    /// <summary>Gets optional structured evidence details.</summary>
    public JsonElement? Data { get; init; }

    /// <summary>Deconstructs the evidence item.</summary>
    public void Deconstruct(
        out string Kind,
        out string Description,
        out JsonElement? Data)
    {
        Kind = this.Kind;
        Description = this.Description;
        Data = this.Data;
    }
}

/// <summary>Health reported after managed plugin initialization.</summary>
public sealed record PluginHealth
{
    /// <summary>Creates one plugin-health report.</summary>
    /// <param name="State">Current readiness state.</param>
    /// <param name="Message">Optional human-readable summary.</param>
    /// <param name="Details">Optional structured string details.</param>
    public PluginHealth(
        PluginHealthState State,
        string? Message = null,
        IReadOnlyDictionary<string, string>? Details = null)
    {
        this.State = State;
        this.Message = Message;
        this.Details = Details;
    }

    /// <summary>Gets the current readiness state.</summary>
    public PluginHealthState State { get; init; }

    /// <summary>Gets an optional human-readable summary.</summary>
    public string? Message { get; init; }

    /// <summary>Gets optional structured string details.</summary>
    public IReadOnlyDictionary<string, string>? Details { get; init; }

    /// <summary>Deconstructs the plugin-health report.</summary>
    public void Deconstruct(
        out PluginHealthState State,
        out string? Message,
        out IReadOnlyDictionary<string, string>? Details)
    {
        State = this.State;
        Message = this.Message;
        Details = this.Details;
    }
}
