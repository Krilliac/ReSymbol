using System.Security.Cryptography;

namespace ReSymbol.ManagedHost;

internal sealed record HostPaths(string PluginRoot, string BinaryPath)
{
    internal static HostPaths Parse(IReadOnlyList<string> arguments)
    {
        if (arguments is not ["--plugin-root", var pluginRoot, "--binary", var binaryPath])
        {
            throw new HostException(
                "expected --plugin-root <DIRECTORY> --binary <EXACT_BINARY>");
        }
        return new HostPaths(
            PathPolicy.RequireRealDirectory(pluginRoot, "plugin root"),
            PathPolicy.RequireRealFile(binaryPath, "exact source binary"));
    }
}

internal static class PathPolicy
{
    private static readonly char[] PackageSeparators = ['/', '\\'];
    private static readonly char[] NonPortablePackageCharacters = ['<', '>', '"', '|', '?', '*'];
    private static readonly HashSet<string> ReservedPackageBasenames = new(
        [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ],
        StringComparer.OrdinalIgnoreCase);

    internal static string RequireRealDirectory(string path, string description)
    {
        var fullPath = RequireAbsolute(path, description);
        if (!Directory.Exists(fullPath))
        {
            throw new HostException($"{description} is not a directory");
        }

        // The parent process is allowed to identify a package through an
        // existing filesystem alias (for example /var on macOS). Resolve that
        // alias once and use the resulting root for every containment check.
        return CanonicalizeExistingDirectory(fullPath, description);
    }

    internal static string RequireRealFile(string path, string description)
    {
        var fullPath = RequireAbsolute(path, description);
        var fileName = Path.GetFileName(fullPath);
        var parent = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(fileName) || string.IsNullOrEmpty(parent) ||
            !Directory.Exists(parent))
        {
            throw new HostException($"{description} is not a regular file");
        }

        // Resolve aliases in the parent path, but never accept the supplied
        // file itself as a link. The exact-file checks below then operate on a
        // stable, explicit path within the canonical parent.
        var canonicalParent = CanonicalizeExistingDirectory(parent, description);
        var canonicalPath = Path.GetFullPath(Path.Combine(canonicalParent, fileName));
        RequireRegularUnlinkedFile(canonicalPath, description);
        return canonicalPath;
    }

    internal static string NormalizePackageRelativePath(
        string value,
        string description = "package path")
    {
        if (string.IsNullOrWhiteSpace(value) || value[0] is '/' or '\\')
        {
            throw new HostException($"{description} must be a non-empty relative path");
        }
        if (value.IndexOf('\0') >= 0 || value.IndexOf(':') >= 0)
        {
            throw new HostException(
                $"{description} contains a NUL character or unsupported ':' syntax");
        }

        // Interpret both slash spellings as package separators on every host.
        // Split without RemoveEmptyEntries so aliases such as a//b, a\\\\b,
        // and trailing separators are rejected instead of silently rewritten.
        var components = value.Split(PackageSeparators, StringSplitOptions.None);
        foreach (var component in components)
        {
            if (string.IsNullOrWhiteSpace(component) || component is "." or ".." ||
                component.Any(char.IsControl) ||
                component.IndexOfAny(NonPortablePackageCharacters) >= 0 ||
                component.EndsWith(' ') || component.EndsWith('.') ||
                ReservedPackageBasenames.Contains(component.Split('.')[0]))
            {
                throw new HostException($"{description} contains a non-portable path component");
            }
        }
        return string.Join('/', components);
    }

    internal static string ResolvePackageFile(
        string pluginRoot,
        string relativePath,
        string description)
    {
        var normalized = NormalizePackageRelativePath(relativePath, description);
        var platformRelativePath = Path.Combine(normalized.Split('/'));
        var fullPath = Path.GetFullPath(Path.Combine(pluginRoot, platformRelativePath));
        if (!IsWithin(pluginRoot, fullPath))
        {
            throw new HostException($"{description} escapes the plugin root");
        }

        RejectLinkedDescendants(pluginRoot, fullPath, description);
        RequireRegularUnlinkedFile(fullPath, description);
        return fullPath;
    }

    internal static bool IsWithin(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative != ".." &&
            !relative.StartsWith($"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal) &&
            !Path.IsPathFullyQualified(relative);
    }

    internal static async ValueTask<byte[]> ReadExactFileAsync(
        string path,
        long maximumBytes,
        string description,
        CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(path);
        if (info.Length < 0 || info.Length > maximumBytes || info.Length > int.MaxValue)
        {
            throw new HostException($"{description} exceeds the {maximumBytes}-byte limit");
        }
        var expectedLength = checked((int)info.Length);
        var bytes = GC.AllocateUninitializedArray<byte>(expectedLength);
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var position = 0;
        while (position < bytes.Length)
        {
            var read = await stream.ReadAsync(bytes.AsMemory(position), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new HostException($"{description} changed while it was read");
            }
            position += read;
        }
        if (stream.ReadByte() != -1)
        {
            throw new HostException($"{description} changed while it was read");
        }
        return bytes;
    }

    internal static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    internal static async ValueTask VerifyExactSha256Async(
        string path,
        long expectedLength,
        string expectedSha256,
        string description,
        CancellationToken cancellationToken = default)
    {
        _ = RequireRealFile(path, description);
        var info = new FileInfo(path);
        if (info.Length != expectedLength)
        {
            throw new HostException($"{description} changed size");
        }
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var actual = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        var expected = Convert.FromHexString(expectedSha256);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected) ||
            stream.Position != expectedLength)
        {
            throw new HostException($"{description} changed contents");
        }
    }

    private static string RequireAbsolute(string path, string description)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new HostException($"{description} path must be explicit and absolute");
        }
        return Path.GetFullPath(path);
    }

    private static string CanonicalizeExistingDirectory(
        string fullPath,
        string description)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new HostException($"{description} has no filesystem root");
        var relative = fullPath[root.Length..];
        var components = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        try
        {
            foreach (var component in components)
            {
                var candidate = Path.GetFullPath(Path.Combine(current, component));
                if (!Directory.Exists(candidate))
                {
                    throw new HostException($"{description} is not a directory");
                }
                var info = new DirectoryInfo(candidate);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0)
                {
                    current = candidate;
                    continue;
                }

                var target = info.ResolveLinkTarget(returnFinalTarget: true);
                if (target is null || !Directory.Exists(target.FullName))
                {
                    throw new HostException(
                        $"{description} contains an unresolved directory link");
                }
                current = Path.GetFullPath(target.FullName);
            }
        }
        catch (HostException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or
                                         UnauthorizedAccessException or
                                         NotSupportedException)
        {
            throw new HostException($"{description} cannot be canonicalized", exception);
        }
        return Path.TrimEndingDirectorySeparator(current);
    }

    private static void RejectLinkedDescendants(
        string root,
        string fullPath,
        string description)
    {
        var relative = Path.GetRelativePath(root, fullPath);
        var components = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        foreach (var component in components)
        {
            current = Path.Combine(current, component);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                continue;
            }
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new HostException(
                    $"{description} path contains a link or reparse point beneath " +
                    "the plugin root");
            }
        }
    }

    private static void RequireRegularUnlinkedFile(string path, string description)
    {
        if (!File.Exists(path))
        {
            throw new HostException($"{description} is not a regular file");
        }
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.Directory) != 0 ||
            (attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new HostException($"{description} must be a regular, unlinked file");
        }
    }
}
