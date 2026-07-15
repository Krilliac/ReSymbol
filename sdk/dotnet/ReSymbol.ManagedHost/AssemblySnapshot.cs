using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace ReSymbol.ManagedHost;

internal sealed record ManagedAssemblyIdentity(
    string Name,
    Version Version,
    string CultureName,
    string PublicKeyToken,
    AssemblyContentType ContentType)
{
    internal string Key =>
        $"{Name}, Version={Version}, Culture={CultureDisplay}, " +
        $"PublicKeyToken={TokenDisplay}, ContentType={ContentType}";

    internal string DisplayName => ContentType == AssemblyContentType.Default
        ? $"{Name}, Version={Version}, Culture={CultureDisplay}, " +
          $"PublicKeyToken={TokenDisplay}"
        : Key;

    private string CultureDisplay => CultureName.Length == 0 ? "neutral" : CultureName;

    private string TokenDisplay => PublicKeyToken.Length == 0 ? "null" : PublicKeyToken;

    internal static ManagedAssemblyIdentity Read(
        byte[] bytes,
        string relativePath)
    {
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (!peReader.HasMetadata)
            {
                throw new HostException(
                    $"managed assembly closure contains a native image: {relativePath}");
            }
            var metadata = peReader.GetMetadataReader();
            if (!metadata.IsAssembly)
            {
                throw new HostException(
                    $"managed assembly closure contains a netmodule: {relativePath}");
            }

            var definition = metadata.GetAssemblyDefinition();
            var assemblyName = new AssemblyName
            {
                Name = metadata.GetString(definition.Name),
                Version = definition.Version,
                CultureName = definition.Culture.IsNil
                    ? null
                    : metadata.GetString(definition.Culture),
                ContentType = (definition.Flags & AssemblyFlags.WindowsRuntime) != 0
                    ? AssemblyContentType.WindowsRuntime
                    : AssemblyContentType.Default,
            };
            if (!definition.PublicKey.IsNil)
            {
                assemblyName.SetPublicKey(metadata.GetBlobBytes(definition.PublicKey));
            }
            return FromAssemblyName(assemblyName, requireVersion: true, relativePath);
        }
        catch (HostException)
        {
            throw;
        }
        catch (Exception exception) when (exception is BadImageFormatException or
                                         IOException or
                                         ArgumentException or
                                         InvalidOperationException)
        {
            throw new HostException(
                $"managed assembly metadata is invalid: {relativePath}", exception);
        }
    }

    internal static ManagedAssemblyIdentity FromRequested(AssemblyName requested) =>
        FromAssemblyName(requested, requireVersion: true, "requested dependency");

    private static ManagedAssemblyIdentity FromAssemblyName(
        AssemblyName assemblyName,
        bool requireVersion,
        string description)
    {
        var name = assemblyName.Name;
        var version = assemblyName.Version;
        if (string.IsNullOrWhiteSpace(name) || name.Any(char.IsControl) ||
            (requireVersion && version is null))
        {
            throw new HostException($"{description} has an incomplete assembly identity");
        }
        byte[] token;
        try
        {
            token = assemblyName.GetPublicKeyToken() ?? [];
        }
        catch (Exception exception) when (exception is ArgumentException or
                                         InvalidOperationException)
        {
            throw new HostException($"{description} has an invalid public key", exception);
        }
        return new ManagedAssemblyIdentity(
            name,
            version!,
            assemblyName.CultureName ?? string.Empty,
            Convert.ToHexString(token).ToLowerInvariant(),
            assemblyName.ContentType);
    }
}

internal sealed record SnapshotFile(
    string RelativePath,
    string FullPath,
    string Sha256,
    byte[] Bytes,
    ManagedAssemblyIdentity Identity);

internal sealed class AssemblySnapshot
{
    private readonly IReadOnlyList<SnapshotFile> files;
    private readonly IReadOnlyDictionary<string, SnapshotFile> filesBySimpleName;
    private readonly IReadOnlyDictionary<string, SnapshotFile> filesByFullIdentity;
    private readonly SnapshotFile entry;
    private readonly long totalBytes;

    private AssemblySnapshot(
        SnapshotFile entry,
        IReadOnlyList<SnapshotFile> files,
        IReadOnlyDictionary<string, SnapshotFile> filesBySimpleName,
        IReadOnlyDictionary<string, SnapshotFile> filesByFullIdentity,
        long totalBytes)
    {
        this.entry = entry;
        this.files = files;
        this.filesBySimpleName = filesBySimpleName;
        this.filesByFullIdentity = filesByFullIdentity;
        this.totalBytes = totalBytes;
    }

    internal string EntryAssembly => entry.RelativePath;

    internal IReadOnlyList<SnapshotFile> Files => files;

    internal long TotalBytes => totalBytes;

    internal static async ValueTask<AssemblySnapshot> CreateAsync(
        string pluginRoot,
        ManagedHostBootstrap bootstrap,
        ulong advertisedMemoryBytes,
        CancellationToken cancellationToken)
    {
        var entryPath = PathPolicy.NormalizePackageRelativePath(
            bootstrap.EntryAssembly,
            "entry assembly");
        var maximumBytes = Math.Min(
            (long)Math.Min(advertisedMemoryBytes, (ulong)(512L * 1024 * 1024)),
            int.MaxValue);
        var totalBytes = 0L;
        var files = new List<SnapshotFile>(bootstrap.Assemblies.Count);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var resolvedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bySimpleName = new Dictionary<string, SnapshotFile>(
            StringComparer.OrdinalIgnoreCase);
        var byFullIdentity = new Dictionary<string, SnapshotFile>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var expected in bootstrap.Assemblies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = PathPolicy.NormalizePackageRelativePath(
                expected.Path,
                "managed assembly path");
            if (!string.Equals(Path.GetExtension(relativePath), ".dll",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new HostException("managed assembly closure may contain only .dll files");
            }
            if (!paths.Add(relativePath))
            {
                throw new HostException(
                    "managed assembly closure contains a path alias or case collision");
            }

            var fullPath = PathPolicy.ResolvePackageFile(
                pluginRoot,
                relativePath,
                "managed assembly");
            if (!resolvedPaths.Add(Path.GetFullPath(fullPath)))
            {
                throw new HostException(
                    "managed assembly closure resolves multiple paths to the same file");
            }
            var remaining = maximumBytes - totalBytes;
            var bytes = await PathPolicy.ReadExactFileAsync(
                fullPath,
                remaining,
                "managed assembly closure",
                cancellationToken).ConfigureAwait(false);
            totalBytes = checked(totalBytes + bytes.LongLength);
            var actualSha256 = PathPolicy.Sha256Hex(bytes);
            if (!string.Equals(actualSha256, expected.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new HostException(
                    $"managed assembly hash does not match the host-owned closure: " +
                    relativePath);
            }

            var identity = ManagedAssemblyIdentity.Read(bytes, relativePath);
            var file = new SnapshotFile(
                relativePath,
                fullPath,
                actualSha256,
                bytes,
                identity);
            if (!byFullIdentity.TryAdd(identity.Key, file))
            {
                throw new HostException(
                    $"managed assembly closure repeats identity '{identity.DisplayName}'");
            }
            if (!bySimpleName.TryAdd(identity.Name, file))
            {
                var prior = bySimpleName[identity.Name];
                throw new HostException(
                    $"managed assembly closure has ambiguous simple name '{identity.Name}' " +
                    $"({prior.RelativePath} and {relativePath})");
            }
            files.Add(file);
        }

        var entry = files.SingleOrDefault(file => string.Equals(
            file.RelativePath,
            entryPath,
            StringComparison.Ordinal))
            ?? throw new HostException("entry assembly is absent from the verified closure");
        return new AssemblySnapshot(entry, files, bySimpleName, byFullIdentity, totalBytes);
    }

    internal SnapshotFile Entry() => entry;

    internal SnapshotFile? ResolveAssembly(AssemblyName requested)
    {
        var simpleName = requested.Name;
        if (string.IsNullOrWhiteSpace(simpleName))
        {
            throw new HostException("plugin requested an assembly without a simple name");
        }
        if (!filesBySimpleName.TryGetValue(simpleName, out var candidate))
        {
            return null;
        }

        ManagedAssemblyIdentity requestedIdentity;
        try
        {
            requestedIdentity = ManagedAssemblyIdentity.FromRequested(requested);
        }
        catch (HostException exception)
        {
            throw new FileLoadException(
                $"plugin requested private dependency '{simpleName}' without a complete " +
                "identity",
                exception);
        }
        if (!filesByFullIdentity.TryGetValue(requestedIdentity.Key, out var exact) ||
            !ReferenceEquals(exact, candidate))
        {
            throw new FileLoadException(
                $"plugin requires {requestedIdentity.DisplayName}, but its verified closure " +
                $"provides {candidate.Identity.DisplayName}");
        }
        return exact;
    }

    internal void RejectReservedSimpleNames(
        IReadOnlySet<string> trustedPlatformAssemblies,
        string managedSdkSimpleName)
    {
        foreach (var file in files)
        {
            if (string.Equals(file.Identity.Name, managedSdkSimpleName,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new HostException(
                    "managed assembly closure must not provide the host's managed SDK");
            }
            if (trustedPlatformAssemblies.Contains(file.Identity.Name))
            {
                throw new HostException(
                    $"managed assembly closure must not shadow platform assembly " +
                    $"'{file.Identity.Name}'");
            }
        }
    }

    internal async ValueTask VerifySourcesAsync(CancellationToken cancellationToken)
    {
        foreach (var file in files)
        {
            await PathPolicy.VerifyExactSha256Async(
                file.FullPath,
                file.Bytes.LongLength,
                file.Sha256,
                "managed assembly post-run verification",
                cancellationToken).ConfigureAwait(false);
        }
    }
}
