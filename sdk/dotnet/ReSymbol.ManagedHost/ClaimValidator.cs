using System.Text.Json;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal static class ClaimValidator
{
    internal static void Validate(SymbolClaim claim, string binarySha256)
    {
        if (claim is null)
        {
            throw new HostException("claim must not be null");
        }
        if (!double.IsFinite(claim.Confidence) || claim.Confidence is < 0 or > 1)
        {
            throw new HostException("claim confidence must be finite and in 0..=1");
        }
        ValidateSubject(claim.Subject, binarySha256);
        ValidateAssertion(claim.Claim);
        if (claim.Evidence is null || claim.Evidence.Count == 0)
        {
            throw new HostException("claim evidence must not be empty");
        }
        foreach (var evidence in claim.Evidence)
        {
            if (evidence is null || string.IsNullOrWhiteSpace(evidence.Description) ||
                !IsEvidenceKind(evidence.Kind) ||
                evidence.Data is { ValueKind: JsonValueKind.Undefined })
            {
                throw new HostException("claim contains invalid evidence");
            }
        }
    }

    private static void ValidateSubject(JsonElement subject, string binarySha256)
    {
        RequireObject(subject, "claim subject");
        var kind = RequireString(subject, "kind", "claim subject");
        var binary = RequireString(subject, "binary", "claim subject");
        if (!string.Equals(binary, binarySha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new HostException("claim subject names a different binary identity");
        }
        switch (kind)
        {
            case "function":
            case "global":
                RequireProperties(subject, ["kind", "binary", "rva"], ["size"]);
                var rva = RequireUInt64(subject, "rva", "claim subject");
                if (subject.TryGetProperty("size", out var size) &&
                    size.ValueKind != JsonValueKind.Null)
                {
                    if (!size.TryGetUInt64(out var sizeValue) || sizeValue == 0)
                    {
                        throw new HostException("claim subject size must be null or nonzero");
                    }
                    if (rva > ulong.MaxValue - sizeValue)
                    {
                        throw new HostException("claim subject address range overflows");
                    }
                }
                break;
            case "type":
                RequireProperties(subject, ["kind", "binary", "key"], []);
                _ = RequireNonWhitespaceString(subject, "key", "claim subject");
                break;
            default:
                throw new HostException("claim subject has an unsupported kind");
        }
    }

    private static void ValidateAssertion(JsonElement assertion)
    {
        RequireObject(assertion, "claim assertion");
        var kind = RequireString(assertion, "kind", "claim assertion");
        switch (kind)
        {
            case "name":
                RequireProperties(assertion, ["kind", "name"], []);
                _ = RequireNonWhitespaceString(assertion, "name", "claim assertion");
                break;
            case "function-prototype":
            case "type-definition":
                RequireProperties(assertion, ["kind", "declaration"], []);
                _ = RequireNonWhitespaceString(
                    assertion, "declaration", "claim assertion");
                break;
            case "function-boundary":
                RequireProperties(assertion, ["kind", "size"], []);
                if (RequireUInt64(assertion, "size", "claim assertion") == 0)
                {
                    throw new HostException("function boundary size must be nonzero");
                }
                break;
            case "function-entry":
                RequireProperties(assertion, ["kind"], []);
                break;
            case "direct-call":
                RequireProperties(assertion, ["kind", "call_site_rva", "target"], []);
                _ = RequireUInt64(assertion, "call_site_rva", "claim assertion");
                ValidateTarget(assertion.GetProperty("target"));
                break;
            case "thunk-target":
                RequireProperties(assertion, ["kind", "target"], []);
                ValidateTarget(assertion.GetProperty("target"));
                break;
            case "string-literal":
                RequireProperties(assertion, ["kind", "encoding", "value"], []);
                ValidateStringLiteral(
                    RequireString(assertion, "encoding", "claim assertion"),
                    RequireNonWhitespaceString(assertion, "value", "claim assertion"));
                break;
            case "data-reference":
                RequireProperties(
                    assertion,
                    ["kind", "instruction_rva", "instruction_size", "target_rva"],
                    []);
                _ = RequireUInt64(assertion, "instruction_rva", "claim assertion");
                var instructionSize = RequireUInt64(
                    assertion, "instruction_size", "claim assertion");
                if (instructionSize is 0 or > byte.MaxValue)
                {
                    throw new HostException("data-reference instruction size is invalid");
                }
                _ = RequireUInt64(assertion, "target_rva", "claim assertion");
                break;
            case "class-membership":
                RequireProperties(assertion, ["kind", "class_name"], []);
                _ = RequireNonWhitespaceString(
                    assertion, "class_name", "claim assertion");
                break;
            case "comment":
                RequireProperties(assertion, ["kind", "text"], []);
                _ = RequireNonWhitespaceString(assertion, "text", "claim assertion");
                break;
            default:
                throw new HostException("claim assertion has an unsupported kind");
        }
    }

    private static void ValidateTarget(JsonElement target)
    {
        RequireObject(target, "control-flow target");
        switch (RequireString(target, "kind", "control-flow target"))
        {
            case "function":
                RequireProperties(target, ["kind", "rva"], []);
                _ = RequireUInt64(target, "rva", "control-flow target");
                break;
            case "import-iat":
                RequireProperties(target, ["kind", "iat_rva"], []);
                _ = RequireUInt64(target, "iat_rva", "control-flow target");
                break;
            case "function-pointer":
                RequireProperties(target, ["kind", "slot_rva", "rva"], []);
                _ = RequireUInt64(target, "slot_rva", "control-flow target");
                _ = RequireUInt64(target, "rva", "control-flow target");
                break;
            default:
                throw new HostException("control-flow target has an unsupported kind");
        }
    }

    private static void ValidateStringLiteral(string encoding, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new HostException("claim string text must not be whitespace-only");
        }
        if (encoding == "ascii")
        {
            if (value.Any(character => character is < ' ' or > '~'))
            {
                throw new HostException("ASCII claim text contains a non-printable character");
            }
            return;
        }
        if (encoding != "utf-16-le" || string.IsNullOrWhiteSpace(value) ||
            value.Any(char.IsControl))
        {
            throw new HostException("UTF-16LE claim text is invalid");
        }
        for (var index = 0; index < value.Length; index++)
        {
            if (char.IsHighSurrogate(value[index]))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    throw new HostException("UTF-16LE claim text has an invalid surrogate pair");
                }
            }
            else if (char.IsLowSurrogate(value[index]))
            {
                throw new HostException("UTF-16LE claim text has an invalid surrogate pair");
            }
        }
    }

    private static void RequireProperties(
        JsonElement value,
        IReadOnlyCollection<string> required,
        IReadOnlyCollection<string> optional)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!seen.Add(property.Name) ||
                (!required.Contains(property.Name) && !optional.Contains(property.Name)))
            {
                throw new HostException("claim JSON contains an unknown or duplicate property");
            }
        }
        if (required.Any(name => !seen.Contains(name)))
        {
            throw new HostException("claim JSON is missing a required property");
        }
    }

    private static void RequireObject(JsonElement value, string description)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new HostException($"{description} must be an object");
        }
    }

    private static string RequireString(
        JsonElement value,
        string property,
        string description)
    {
        if (!value.TryGetProperty(property, out var element) ||
            element.ValueKind != JsonValueKind.String)
        {
            throw new HostException($"{description}.{property} must be a string");
        }
        return element.GetString() ?? string.Empty;
    }

    private static string RequireNonWhitespaceString(
        JsonElement value,
        string property,
        string description)
    {
        var result = RequireString(value, property, description);
        if (string.IsNullOrWhiteSpace(result))
        {
            throw new HostException(
                $"{description}.{property} must not be empty or whitespace-only");
        }
        return result;
    }

    private static ulong RequireUInt64(
        JsonElement value,
        string property,
        string description)
    {
        if (!value.TryGetProperty(property, out var element) ||
            !element.TryGetUInt64(out var result))
        {
            throw new HostException($"{description}.{property} must be an unsigned integer");
        }
        return result;
    }

    private static bool IsEvidenceKind(string? value) =>
        value is not null &&
        value.Length is >= 2 and <= 128 &&
        value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');
}
