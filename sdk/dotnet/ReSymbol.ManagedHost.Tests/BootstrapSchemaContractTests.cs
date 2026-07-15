using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ReSymbol.ManagedHost;

internal static class BootstrapSchemaContractTests
{
    private const string SchemaRelativePath =
        "sdk/dotnet/ReSymbol.ManagedHost/managed-host-bootstrap.schema.json";

    internal static Task RunAsync()
    {
        using var schema = JsonDocument.Parse(
            File.ReadAllBytes(FindSchema()),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
        var root = schema.RootElement;

        Require(root.GetProperty("$schema").GetString() ==
            "https://json-schema.org/draft/2020-12/schema",
            "bootstrap schema must declare JSON Schema 2020-12");
        Require(root.GetProperty("additionalProperties").ValueKind == JsonValueKind.False,
            "bootstrap schema must reject unknown root properties");
        RequireSet(
            root.GetProperty("required"),
            [
                "protocol",
                "version",
                "expected_artifact_sha256",
                "entry_assembly",
                "expected_plugin",
                "assemblies",
                "output_limits",
                "service_limits",
                "binary",
                "image",
            ],
            "bootstrap required fields");

        var definitions = root.GetProperty("$defs");
        ValidatePortableDllRule(definitions.GetProperty("relativeDll"));
        ValidateTextRule(
            definitions.GetProperty("expectedPlugin").GetProperty("properties")
                .GetProperty("name"),
            4096,
            "expected plugin name");
        ValidateTextRule(
            definitions.GetProperty("expectedPlugin").GetProperty("properties")
                .GetProperty("version"),
            128,
            "expected plugin version");

        var identifier = definitions.GetProperty("identifier");
        Require(identifier.GetProperty("minLength").GetInt32() == 3,
            "identifier minimum must match the host");
        Require(identifier.GetProperty("maxLength").GetInt32() ==
            ProtocolConstants.MaxIdentifierBytes,
            "identifier maximum must match the host");
        var identifierPattern = Compile(identifier.GetProperty("pattern").GetString());
        foreach (var accepted in new[] { "abc", "dev.resymbol.plugin-1", "a_b.c-d" })
        {
            Require(SchemaStringAccepts(identifier, identifierPattern, accepted),
                $"identifier schema unexpectedly rejects '{accepted}'");
        }
        foreach (var rejected in new[] { "ab", "Upper", "-abc", "abc.", "a..b" })
        {
            Require(!SchemaStringAccepts(identifier, identifierPattern, rejected),
                $"identifier schema unexpectedly accepts '{rejected}'");
        }

        var assemblies = root.GetProperty("properties").GetProperty("assemblies");
        Require(assemblies.GetProperty("minItems").GetInt32() == 1,
            "assembly closure must be non-empty");
        Require(assemblies.GetProperty("maxItems").GetInt32() ==
            ProtocolConstants.MaxAssemblyEntries,
            "assembly closure maximum must match the host");

        var output = root.GetProperty("properties").GetProperty("output_limits")
            .GetProperty("properties");
        RequireRange(output.GetProperty("max_messages"), 2, 1_000_000,
            "max_messages");
        RequireRange(output.GetProperty("max_stdout_bytes"), 1024,
            ProtocolConstants.HardMaxStdoutBytes, "max_stdout_bytes");

        var binary = definitions.GetProperty("binary").GetProperty("properties");
        RequireRange(binary.GetProperty("size"), 0,
            ProtocolConstants.HardMaxBinaryBytes, "binary.size");
        Require(binary.GetProperty("format").GetProperty("const").GetString() == "pe",
            "managed bootstrap must bind PE input");
        Require(binary.GetProperty("architecture").GetProperty("const").GetString() ==
            "x86_64", "managed bootstrap must bind x86_64 input");
        RequireUnsignedRange(binary.GetProperty("image_base"), 0, ulong.MaxValue,
            "binary.image_base");

        var service = root.GetProperty("properties").GetProperty("service_limits")
            .GetProperty("properties").GetProperty("max_binary_read_bytes");
        RequireRange(service, 0, ProtocolConstants.HardMaxBinaryBytes,
            "max_binary_read_bytes");

        var image = definitions.GetProperty("peImage").GetProperty("properties");
        RequireUnsignedRange(image.GetProperty("size_of_headers"), 1, uint.MaxValue,
            "image.size_of_headers");
        RequireUnsignedRange(image.GetProperty("size_of_image"), 1, uint.MaxValue,
            "image.size_of_image");
        Require(image.GetProperty("sections").GetProperty("maxItems").GetInt32() == 96,
            "PE section maximum must match the host");

        var deadline = root.GetProperty("properties").GetProperty("deadline_unix_ms");
        Require(deadline.GetProperty("minimum").GetInt64() == long.MinValue &&
            deadline.GetProperty("maximum").GetInt64() == long.MaxValue,
            "deadline_unix_ms must match the signed 64-bit wire model");

        var comment = root.GetProperty("$comment").GetString() ?? string.Empty;
        Require(comment.Contains("262144 UTF-8 bytes", StringComparison.Ordinal) &&
            comment.Contains("ordinal case-insensitive", StringComparison.Ordinal),
            "schema must publish non-expressible bootstrap and path invariants");
        return Task.CompletedTask;
    }

    private static void ValidatePortableDllRule(JsonElement rule)
    {
        Require(rule.GetProperty("minLength").GetInt32() == 5,
            "portable DLL rule must require a non-empty basename");
        var pattern = Compile(rule.GetProperty("pattern").GetString());

        foreach (var accepted in new[]
        {
            "a.dll",
            "Plugin.DLL",
            "lib/Plugin.dLl",
            @"lib\Plugin.dll",
            " leading/Plugin.dll",
            "space ok/Plugin .dll",
            "naïve/Plugin.dll",
            "COM0/Plugin.dll",
            "COM10/Plugin.dll",
            "CONSOLE/Plugin.dll",
        })
        {
            Require(ProductionPortableDllAccepts(accepted),
                $"portable-path test has an invalid accepted fixture: '{accepted}'");
            Require(SchemaStringAccepts(rule, pattern, accepted),
                $"relativeDll schema unexpectedly rejects '{accepted}'");
        }

        foreach (var rejected in new[]
        {
            "",
            ".dll",
            "Plugin.exe",
            "/Plugin.dll",
            @"\Plugin.dll",
            @"C:\Plugin.dll",
            "./Plugin.dll",
            "../Plugin.dll",
            "a/./Plugin.dll",
            "a/../Plugin.dll",
            "a//Plugin.dll",
            @"a\\Plugin.dll",
            @"a/\Plugin.dll",
            " /Plugin.dll",
            "a/\u00a0/Plugin.dll",
            "a\0/Plugin.dll",
            "a\n/Plugin.dll",
            "bad:name.dll",
            "bad<name.dll",
            "bad>name.dll",
            "bad\"name.dll",
            "bad|name.dll",
            "bad?name.dll",
            "bad*name.dll",
            "dir /Plugin.dll",
            "dir./Plugin.dll",
            "CON.dll",
            "prn.txt.dll",
            "AUX/Plugin.dll",
            "nul/Plugin.dll",
            "com1/Plugin.dll",
            "Lpt9.data/Plugin.dll",
            "ReSymbol.PluginSdk.dll",
            "lib/resymbol.pluginsdk.DLL",
        })
        {
            Require(!ProductionPortableDllAccepts(rejected),
                $"portable-path test has an invalid rejected fixture: '{Printable(rejected)}'");
            Require(!SchemaStringAccepts(rule, pattern, rejected),
                $"relativeDll schema unexpectedly accepts '{Printable(rejected)}'");
        }
    }

    private static void ValidateTextRule(JsonElement rule, int maximumUtf8Bytes,
        string description)
    {
        Require(rule.GetProperty("minLength").GetInt32() == 1,
            $"{description} must be non-empty");
        Require(rule.GetProperty("maxLength").GetInt32() == maximumUtf8Bytes,
            $"{description} character ceiling must match its ASCII wire ceiling");
        Require(rule.GetProperty("x-resymbol-maxUtf8Bytes").GetInt32() == maximumUtf8Bytes,
            $"{description} must publish its exact UTF-8 byte ceiling");
        var pattern = Compile(rule.GetProperty("pattern").GetString());
        Require(SchemaStringAccepts(rule, pattern, "Managed plugin"),
            $"{description} rejects ordinary text");
        Require(!SchemaStringAccepts(rule, pattern, "bad\ntext"),
            $"{description} permits a newline control");
        Require(!SchemaStringAccepts(rule, pattern, "bad\0text"),
            $"{description} permits a NUL control");
        Require(!SchemaStringAccepts(rule, pattern, $"bad{(char)0x85}text"),
            $"{description} permits a C1 control");
        Require(!SchemaStringAccepts(rule, pattern, new string('x', maximumUtf8Bytes + 1)),
            $"{description} permits an oversized ASCII value");
        var multibyte = string.Concat(Enumerable.Repeat("\U0001F642", maximumUtf8Bytes / 2));
        Require(!SchemaStringAccepts(rule, pattern, multibyte),
            $"{description} does not enforce its UTF-8 byte annotation");
    }

    private static bool SchemaStringAccepts(JsonElement rule, Regex pattern, string value)
    {
        var runeCount = value.EnumerateRunes().Count();
        if (rule.TryGetProperty("minLength", out var minimum) &&
            runeCount < minimum.GetInt32())
        {
            return false;
        }
        if (rule.TryGetProperty("maxLength", out var maximum) &&
            runeCount > maximum.GetInt32())
        {
            return false;
        }
        if (rule.TryGetProperty("x-resymbol-maxUtf8Bytes", out var byteMaximum) &&
            Encoding.UTF8.GetByteCount(value) > byteMaximum.GetInt32())
        {
            return false;
        }
        return pattern.IsMatch(value);
    }

    private static bool ProductionPortableDllAccepts(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value[0] is '/' or '\\' ||
            value.IndexOfAny([':', '\0']) >= 0)
        {
            return false;
        }
        var components = value.Split(['/', '\\'], StringSplitOptions.None);
        if (components.Any(component => !PortableComponentAccepts(component)))
        {
            return false;
        }
        var fileName = components[^1];
        var separator = fileName.LastIndexOf('.');
        return separator > 0 &&
            fileName[(separator + 1)..].Equals("dll", StringComparison.OrdinalIgnoreCase) &&
            !fileName.Equals("ReSymbol.PluginSdk.dll", StringComparison.OrdinalIgnoreCase);
    }

    private static bool PortableComponentAccepts(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "." or ".." ||
            value.IndexOfAny(['/', '\\', ':', '\0', '<', '>', '"', '|', '?', '*']) >= 0 ||
            value.Any(char.IsControl) || value.EndsWith(' ') || value.EndsWith('.'))
        {
            return false;
        }
        var baseName = value.Split('.')[0];
        return !new[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        }.Contains(baseName, StringComparer.OrdinalIgnoreCase);
    }

    private static Regex Compile(string? pattern)
    {
        Require(!string.IsNullOrEmpty(pattern), "schema string rule is missing its pattern");
        return new Regex(
            pattern!,
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
    }

    private static void RequireRange(JsonElement rule, long minimum, long maximum,
        string description) =>
        Require(rule.GetProperty("minimum").GetInt64() == minimum &&
            rule.GetProperty("maximum").GetInt64() == maximum,
            $"{description} range does not match the host");

    private static void RequireUnsignedRange(JsonElement rule, ulong minimum, ulong maximum,
        string description) =>
        Require(rule.GetProperty("minimum").GetUInt64() == minimum &&
            rule.GetProperty("maximum").GetUInt64() == maximum,
            $"{description} range does not match the wire model");

    private static void RequireSet(JsonElement array, IReadOnlyCollection<string> expected,
        string description)
    {
        var actual = array.EnumerateArray()
            .Select(item => item.GetString() ?? string.Empty)
            .ToHashSet(StringComparer.Ordinal);
        Require(actual.SetEquals(expected) && actual.Count == expected.Count,
            $"{description} do not match the host model");
    }

    private static string FindSchema()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null;
                 directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, SchemaRelativePath);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        throw new FileNotFoundException(
            $"cannot locate {SchemaRelativePath} from the working or test directory");
    }

    private static string Printable(string value) =>
        JsonSerializer.Serialize(value);

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
