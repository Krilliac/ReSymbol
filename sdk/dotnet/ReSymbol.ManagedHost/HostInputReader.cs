using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ReSymbol.ManagedHost;

internal static partial class HostInputReader
{
    private const int MaximumOutputMessages = 1_000_000;

    internal static async ValueTask<HostInput> ReadAsync(
        Stream input,
        CancellationToken cancellationToken = default)
    {
        var reader = new BoundedNdjsonReader(input);
        var bootstrapBytes = await reader.ReadLineAsync(
            "managed-host bootstrap",
            ProtocolConstants.MaxBootstrapBytes,
            cancellationToken).ConfigureAwait(false);
        var bootstrap = StrictJson.Decode<ManagedHostBootstrap>(
            bootstrapBytes,
            "managed-host bootstrap");
        ValidateBootstrap(bootstrap);

        var helloBytes = await reader.ReadLineAsync(
            "plugin hello",
            ProtocolConstants.MaxInitialWireBytes,
            cancellationToken).ConfigureAwait(false);
        var hello = StrictJson.Decode<HostHello>(helloBytes, "plugin hello");
        ValidateHello(hello);
        if (hello.PluginId != bootstrap.ExpectedPlugin.Id)
        {
            throw new HostException(
                "hello plugin identity does not match the host-owned manifest identity");
        }
        var requestedPermissions = bootstrap.ExpectedPlugin.RequestedPermissions
            .ToHashSet(StringComparer.Ordinal);
        if (hello.GrantedPermissions.Any(permission =>
                !requestedPermissions.Contains(permission)))
        {
            throw new HostException(
                "hello grants a permission absent from host-owned expected plugin metadata");
        }
        if (helloBytes.Length > hello.Limits.MaxMessageBytes)
        {
            throw new HostException(
                $"plugin hello exceeds the {hello.Limits.MaxMessageBytes}-byte message limit");
        }
        if (bootstrap.OutputLimits.MaxStdoutBytes < hello.Limits.MaxMessageBytes)
        {
            throw new HostException("max_stdout_bytes must be at least max_message_bytes");
        }

        var requestBytes = await reader.ReadLineAsync(
            "plugin request",
            hello.Limits.MaxMessageBytes,
            cancellationToken).ConfigureAwait(false);
        var request = StrictJson.Decode<HostRequest>(requestBytes, "plugin request");
        ValidateRequest(request, bootstrap, hello.GrantedPermissions);
        await reader.RequireEndAsync(cancellationToken).ConfigureAwait(false);
        WireOutput.ValidateMandatoryOutput(
            bootstrap.ExpectedPlugin,
            request.Id,
            hello.Limits.MaxMessageBytes,
            bootstrap.OutputLimits.MaxStdoutBytes);
        return new HostInput(bootstrap, hello, request);
    }

    internal static void ValidateBootstrap(ManagedHostBootstrap bootstrap)
    {
        ValidateProtocol(bootstrap.Protocol, bootstrap.Version,
            ProtocolConstants.ManagedHost, "managed-host bootstrap");
        ValidateSha256(
            bootstrap.ExpectedArtifactSha256,
            "expected plugin artifact SHA-256");
        ValidateRelativePath(bootstrap.EntryAssembly, "entry assembly");
        ValidateExpectedPlugin(bootstrap.ExpectedPlugin);
        if (bootstrap.Assemblies is null || bootstrap.Assemblies.Count == 0 ||
            bootstrap.Assemblies.Count > ProtocolConstants.MaxAssemblyEntries)
        {
            throw new HostException(
                $"assembly closure must contain 1..{ProtocolConstants.MaxAssemblyEntries} entries");
        }

        // Package paths are portable identities, not host-native path strings.
        // Reject case aliases on every host so a package has one meaning when
        // moved between case-sensitive and case-insensitive filesystems.
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalizedEntry = NormalizeRelativePath(bootstrap.EntryAssembly);
        if (IsHostSdkPath(normalizedEntry))
        {
            throw new HostException(
                "the host-supplied ReSymbol.PluginSdk cannot be the plugin entry assembly");
        }
        var containsEntry = false;
        foreach (var assembly in bootstrap.Assemblies)
        {
            ValidateRelativePath(assembly.Path, "assembly path");
            ValidateSha256(assembly.Sha256, "assembly SHA-256");
            var normalizedAssembly = NormalizeRelativePath(assembly.Path);
            if (IsHostSdkPath(normalizedAssembly))
            {
                throw new HostException(
                    "the host-supplied ReSymbol.PluginSdk must not enter the private closure");
            }
            if (!paths.Add(normalizedAssembly))
            {
                throw new HostException(
                    "assembly closure contains a duplicate path or portable path alias");
            }
            containsEntry |= string.Equals(
                normalizedAssembly,
                normalizedEntry,
                StringComparison.Ordinal);
        }
        if (!containsEntry)
        {
            throw new HostException("assembly closure does not bind the entry assembly");
        }

        var output = bootstrap.OutputLimits;
        if (output.MaxMessages is < 2 or > MaximumOutputMessages)
        {
            throw new HostException($"max_messages must be in 2..={MaximumOutputMessages}");
        }
        if (output.MaxStdoutBytes is < 1024 or > ProtocolConstants.HardMaxStdoutBytes)
        {
            throw new HostException(
                $"max_stdout_bytes must be in 1024..={ProtocolConstants.HardMaxStdoutBytes}");
        }
        if (bootstrap.ServiceLimits.MaxBinaryReadBytes < 0 ||
            bootstrap.ServiceLimits.MaxBinaryReadBytes > ProtocolConstants.HardMaxBinaryBytes)
        {
            throw new HostException("max_binary_read_bytes is outside the supported range");
        }
        ValidateBinary(bootstrap.Binary);
        ValidateImage(bootstrap.Image, bootstrap.Binary.Size);
    }

    internal static void ValidateHello(HostHello hello)
    {
        ValidateProtocol(hello.Protocol, hello.Version,
            ProtocolConstants.PluginWire, "plugin hello");
        if (hello.Kind != "hello")
        {
            throw new HostException("first wire message is not hello");
        }
        ValidateText(hello.SessionId, "session id", ProtocolConstants.MaxIdentifierBytes);
        ValidateIdentifier(hello.PluginId, "plugin id");
        if (hello.GrantedPermissions is null ||
            hello.GrantedPermissions.Count > ProtocolConstants.MaxPermissions)
        {
            throw new HostException("hello contains too many granted permissions");
        }
        var grants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var permission in hello.GrantedPermissions)
        {
            ValidateIdentifier(permission, "granted permission");
            if (!grants.Add(permission))
            {
                throw new HostException("hello contains a duplicate granted permission");
            }
        }
        if (hello.Limits.MaxMessageBytes is < 1024 or > ProtocolConstants.HardMaxStdoutBytes)
        {
            throw new HostException("max_message_bytes is outside the supported range");
        }
        if (hello.Limits.MaxMemoryBytes is < 1_048_576 or >
            (ulong)ProtocolConstants.MaxAdvertisedMemoryBytes)
        {
            throw new HostException("max_memory_bytes is outside the supported range");
        }
        if (hello.Limits.RequestTimeoutMilliseconds is < 1 or >
            ProtocolConstants.MaxTimeoutMilliseconds)
        {
            throw new HostException("request_timeout_ms is outside the supported range");
        }
        if (hello.Isolation is null || hello.Isolation.Mode != "process" ||
            !hello.Isolation.Required)
        {
            throw new HostException("managed helper requires process isolation");
        }
    }

    internal static void ValidateRequest(
        HostRequest request,
        ManagedHostBootstrap bootstrap,
        IReadOnlyList<string> grantedPermissions)
    {
        ValidateProtocol(request.Protocol, request.Version,
            ProtocolConstants.PluginWire, "plugin request");
        if (request.Kind != "request" || request.Direction != "host-to-plugin")
        {
            throw new HostException(
                "second wire message is not a host-to-plugin request");
        }
        ValidateText(request.Id, "request id", ProtocolConstants.MaxIdentifierBytes);
        if (request.Method != "analyze")
        {
            throw new HostException("managed helper supports only analyze requests");
        }
        if (request.Payload.ValueKind != JsonValueKind.Object ||
            !request.Payload.TryGetProperty("binary", out var binaryElement))
        {
            throw new HostException("analyze request is missing its binary identity");
        }
        var binary = StrictJson.Decode<BinaryIdentityModel>(
            Encoding.UTF8.GetBytes(binaryElement.GetRawText()),
            "request binary identity");
        ValidateBinary(binary);
        if (!BinaryEquals(binary, bootstrap.Binary))
        {
            throw new HostException(
                "request binary identity does not match managed-host bootstrap");
        }

        if (request.Payload.TryGetProperty("options", out var options) &&
            options.ValueKind != JsonValueKind.Object)
        {
            throw new HostException("managed request options must be an object");
        }
        var symbolsRead = grantedPermissions.Contains(
            "symbols.read",
            StringComparer.Ordinal);
        if (request.Payload.TryGetProperty("base_analysis", out var baseAnalysis))
        {
            if (!symbolsRead)
            {
                throw new HostException(
                    "managed request includes base analysis without symbols.read permission");
            }
            if (baseAnalysis.ValueKind != JsonValueKind.Object)
            {
                throw new HostException("managed base analysis must be an object");
            }
        }
        else if (symbolsRead)
        {
            throw new HostException(
                "managed request granted symbols.read without supplying base analysis");
        }
    }

    internal static string NormalizeRelativePath(string value) =>
        PathPolicy.NormalizePackageRelativePath(value);

    private static bool IsHostSdkPath(string normalizedPath)
    {
        var separator = normalizedPath.LastIndexOf('/');
        var fileName = normalizedPath[(separator + 1)..];
        return fileName.Equals(
            "ReSymbol.PluginSdk.dll",
            StringComparison.OrdinalIgnoreCase);
    }

    internal static void ValidateIdentifier(string value, string description)
    {
        var byteCount = string.IsNullOrEmpty(value) ? 0 : Encoding.UTF8.GetByteCount(value);
        if (byteCount is < 3 or > ProtocolConstants.MaxIdentifierBytes ||
            !IdentifierPattern().IsMatch(value))
        {
            throw new HostException($"invalid {description}");
        }
    }

    private static void ValidateExpectedPlugin(ExpectedPlugin plugin)
    {
        if (plugin is null)
        {
            throw new HostException("managed bootstrap is missing expected plugin metadata");
        }
        ValidateIdentifier(plugin.Id, "expected plugin id");
        ValidateText(plugin.Name, "expected plugin name", 4096);
        ValidateText(plugin.Version, "expected plugin version", 128);
        ValidateIdentifierList(plugin.Capabilities, "expected plugin capability", 4096);
        ValidateIdentifierList(
            plugin.RequestedPermissions,
            "expected requested permission",
            4096);
    }

    private static void ValidateIdentifierList(
        IReadOnlyList<string> values,
        string description,
        int maximum)
    {
        if (values is null || values.Count > maximum)
        {
            throw new HostException($"{description} list exceeds the supported limit");
        }
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            ValidateIdentifier(value, description);
            if (!unique.Add(value))
            {
                throw new HostException($"{description} list contains a duplicate");
            }
        }
    }

    private static void ValidateBinary(BinaryIdentityModel binary)
    {
        ValidateSha256(binary.Id, "binary SHA-256");
        if (binary.Size > ProtocolConstants.HardMaxBinaryBytes)
        {
            throw new HostException("source binary exceeds the managed-host size limit");
        }
        if (!string.Equals(binary.FormatName, "pe", StringComparison.Ordinal))
        {
            throw new HostException("the first managed host accepts only PE binary maps");
        }
        if (binary.Architecture != "x86_64")
        {
            throw new HostException("the first managed host accepts only x86_64 PE images");
        }
    }

    private static void ValidateImage(PeImageMap image, ulong binarySize)
    {
        if (image is null || image.SizeOfHeaders == 0 || image.SizeOfImage == 0 ||
            image.SizeOfHeaders > image.SizeOfImage || image.SizeOfHeaders > binarySize)
        {
            throw new HostException("PE image and header sizes are inconsistent");
        }
        if (image.Sections is null || image.Sections.Count > 96)
        {
            throw new HostException("PE image map exceeds the 96-section limit");
        }
        var virtualRanges = new List<(ulong Start, ulong End)>();
        var fileRanges = new List<(ulong Start, ulong End)>();
        foreach (var section in image.Sections)
        {
            var virtualSize = section.LoadedSize;
            var virtualEnd = checked((ulong)section.VirtualAddress + virtualSize);
            var rawEnd = checked((ulong)section.RawDataOffset + section.RawDataSize);
            if (virtualEnd > image.SizeOfImage || rawEnd > binarySize)
            {
                throw new HostException("PE section extends beyond the declared image or file");
            }
            if (virtualSize != 0)
            {
                if (section.VirtualAddress < image.SizeOfHeaders)
                {
                    throw new HostException("PE section overlaps the image headers");
                }
                virtualRanges.Add((section.VirtualAddress, virtualEnd));
            }
            if (section.RawDataSize != 0)
            {
                if (section.RawDataOffset < image.SizeOfHeaders)
                {
                    throw new HostException("PE section raw data overlaps the PE headers");
                }
                fileRanges.Add((section.RawDataOffset, rawEnd));
            }
        }
        RequireNonOverlapping(virtualRanges, "virtual");
        RequireNonOverlapping(fileRanges, "file");
    }

    private static void RequireNonOverlapping(
        List<(ulong Start, ulong End)> ranges,
        string description)
    {
        ranges.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (var index = 1; index < ranges.Count; index++)
        {
            if (ranges[index - 1].End > ranges[index].Start)
            {
                throw new HostException($"PE image map contains overlapping {description} ranges");
            }
        }
    }

    private static bool BinaryEquals(BinaryIdentityModel left, BinaryIdentityModel right) =>
        string.Equals(left.Id, right.Id, StringComparison.OrdinalIgnoreCase) &&
        left.Size == right.Size &&
        string.Equals(left.FormatName, right.FormatName, StringComparison.Ordinal) &&
        string.Equals(left.Architecture, right.Architecture, StringComparison.Ordinal) &&
        left.ImageBase == right.ImageBase;

    private static void ValidateProtocol(
        string protocol,
        ProtocolVersion version,
        string expected,
        string description)
    {
        if (protocol != expected || version is null ||
            version.Major != ProtocolConstants.Major ||
            version.Minor != ProtocolConstants.Minor)
        {
            throw new HostException($"unsupported {description} protocol/version");
        }
    }

    private static void ValidateRelativePath(string value, string description)
    {
        _ = PathPolicy.NormalizePackageRelativePath(value, description);
    }

    private static void ValidateSha256(string value, string description)
    {
        if (value is null || value.Length != 64 ||
            value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new HostException($"invalid {description}");
        }
    }

    private static void ValidateText(string value, string description, int maxBytes)
    {
        if (string.IsNullOrEmpty(value) || Encoding.UTF8.GetByteCount(value) > maxBytes ||
            value.Any(char.IsControl))
        {
            throw new HostException($"invalid {description}");
        }
    }

    [GeneratedRegex(
        "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$",
        RegexOptions.CultureInvariant)]
    private static partial Regex IdentifierPattern();
}
