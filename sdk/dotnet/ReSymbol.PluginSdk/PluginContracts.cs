using System.Text.Json;
using System.Text.Json.Serialization;

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

/// <summary>Encoding used to decode a recovered string literal.</summary>
[JsonConverter(typeof(StringEncodingJsonConverter))]
public enum StringEncoding
{
    Ascii,
    Utf16Le,
}

/// <summary>Reads and writes the exact protocol-1 string-encoding names.</summary>
public sealed class StringEncodingJsonConverter : JsonConverter<StringEncoding>
{
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
    public const string StringLiteral = "string-literal";
    public const string DataReference = "data-reference";
}

/// <summary>Canonical payload for a <c>string-literal</c> assertion.</summary>
public sealed record StringLiteralAssertion
{
    [JsonConstructor]
    public StringLiteralAssertion(StringEncoding encoding, string value)
    {
        ClaimAssertions.ValidateStringLiteral(encoding, value);
        Encoding = encoding;
        Value = value;
    }

    [JsonPropertyName("kind")]
    public string Kind => ClaimAssertionKinds.StringLiteral;

    [JsonPropertyName("encoding")]
    public StringEncoding Encoding { get; }

    [JsonPropertyName("value")]
    public string Value { get; }
}

/// <summary>Canonical payload for a <c>data-reference</c> assertion.</summary>
public sealed record DataReferenceAssertion
{
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

    [JsonPropertyName("kind")]
    public string Kind => ClaimAssertionKinds.DataReference;

    [JsonPropertyName("instruction_rva")]
    public ulong InstructionRva { get; }

    [JsonPropertyName("instruction_size")]
    public byte InstructionSize { get; }

    [JsonPropertyName("target_rva")]
    public ulong TargetRva { get; }
}

/// <summary>
/// Creates validated canonical JSON assertions accepted by <see cref="SymbolClaim"/>.
/// </summary>
public static class ClaimAssertions
{
    public static JsonElement StringLiteral(StringEncoding encoding, string value) =>
        JsonSerializer.SerializeToElement(new StringLiteralAssertion(encoding, value));

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
