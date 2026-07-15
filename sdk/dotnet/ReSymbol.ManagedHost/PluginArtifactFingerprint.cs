using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ReSymbol.ManagedHost;

// Exact parity with resymbol-plugin-state's portable v1 directory digest.
// The root plugin.disabled regular file is policy state and is deliberately
// excluded; every other accepted directory and regular file is represented.
internal static class PluginArtifactFingerprint
{
    private const long MaximumFiles = 10_000;
    private const long MaximumEntries = 20_000;
    private const long MaximumFileBytes = 2L * 1024 * 1024 * 1024;
    private const long MaximumTotalBytes = 8L * 1024 * 1024 * 1024;
    private const int MaximumDepth = 32;
    private static readonly byte[] Domain =
        "resymbol.plugin-artifact-fingerprint\0v1\0"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static async ValueTask VerifyAsync(
        string pluginRoot,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        if (expectedSha256.Length != 64 ||
            expectedSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new HostException("invalid expected plugin artifact SHA-256");
        }

        var actual = await ComputeAsync(pluginRoot, cancellationToken).ConfigureAwait(false);
        var expected = Convert.FromHexString(expectedSha256);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new HostException(
                "plugin artifact does not match the host-owned exact fingerprint");
        }
    }

    internal static async ValueTask<byte[]> ComputeAsync(
        string pluginRoot,
        CancellationToken cancellationToken)
    {
        var root = PathPolicy.RequireRealDirectory(pluginRoot, "plugin root");
        var entries = new List<ArtifactEntry>();
        var counters = new TraversalCounters();
        CollectEntries(root, string.Empty, 0, counters, entries, cancellationToken);
        entries.Sort(ArtifactEntryComparer.Instance);

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            hash.AppendData([entry.IsDirectory ? (byte)'d' : (byte)'f']);
            AppendLengthPrefixed(hash, entry.RelativePathUtf8);
            if (!entry.IsDirectory)
            {
                await AppendFileAsync(hash, entry, cancellationToken).ConfigureAwait(false);
            }
        }

        return hash.GetHashAndReset();
    }

    private static void CollectEntries(
        string directory,
        string relativeParent,
        int parentDepth,
        TraversalCounters counters,
        List<ArtifactEntry> entries,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        List<(FileSystemInfo Info, byte[] NameUtf8)> children;
        try
        {
            children = new DirectoryInfo(directory)
                .EnumerateFileSystemInfos()
                .Select(info => (info, EncodePath(info.Name)))
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or
                                         UnauthorizedAccessException or
                                         EncoderFallbackException)
        {
            throw new HostException("cannot enumerate the exact plugin artifact", exception);
        }
        children.Sort(static (left, right) =>
            CompareBytes(left.NameUtf8, right.NameUtf8));

        foreach (var (info, nameUtf8) in children)
        {
            cancellationToken.ThrowIfCancellationRequested();
            counters.VisitedEntries = checked(counters.VisitedEntries + 1);
            if (counters.VisitedEntries > MaximumEntries + 1)
            {
                throw new HostException("plugin artifact traversal entry limit exceeded");
            }

            var depth = checked(parentDepth + 1);
            if (depth > MaximumDepth)
            {
                throw new HostException("plugin artifact path depth limit exceeded");
            }
            info.Refresh();
            var attributes = info.Attributes;
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new HostException("plugin artifact contains a link or reparse point");
            }

            var relative = relativeParent.Length == 0
                ? info.Name
                : $"{relativeParent}/{info.Name}";
            var relativeUtf8 = relativeParent.Length == 0
                ? nameUtf8
                : EncodePath(relative);
            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            if (parentDepth == 0 && info.Name == "plugin.disabled" && !isDirectory)
            {
                continue;
            }

            counters.Entries = checked(counters.Entries + 1);
            if (counters.Entries > MaximumEntries)
            {
                throw new HostException("plugin artifact entry limit exceeded");
            }

            if (isDirectory)
            {
                entries.Add(new ArtifactEntry(info.FullName, relativeUtf8, true, 0));
                CollectEntries(
                    info.FullName,
                    relative,
                    depth,
                    counters,
                    entries,
                    cancellationToken);
                continue;
            }

            if (info is not FileInfo file)
            {
                throw new HostException("plugin artifact contains an unsupported file type");
            }
            file.Refresh();
            var length = file.Length;
            if (length < 0 || length > MaximumFileBytes)
            {
                throw new HostException("plugin artifact file size limit exceeded");
            }
            counters.Files = checked(counters.Files + 1);
            if (counters.Files > MaximumFiles)
            {
                throw new HostException("plugin artifact regular-file limit exceeded");
            }
            counters.TotalBytes = checked(counters.TotalBytes + length);
            if (counters.TotalBytes > MaximumTotalBytes)
            {
                throw new HostException("plugin artifact total-byte limit exceeded");
            }
            entries.Add(new ArtifactEntry(file.FullName, relativeUtf8, false, length));
        }
    }

    private static async ValueTask AppendFileAsync(
        IncrementalHash hash,
        ArtifactEntry entry,
        CancellationToken cancellationToken)
    {
        var length = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(length, checked((ulong)entry.Length));
        hash.AppendData(length);

        FileInfo before;
        try
        {
            before = new FileInfo(entry.FullPath);
            before.Refresh();
            if (!before.Exists || before.Length != entry.Length ||
                (before.Attributes & (FileAttributes.Directory |
                                      FileAttributes.ReparsePoint)) != 0)
            {
                throw new HostException("plugin artifact file changed before hashing");
            }
        }
        catch (HostException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or
                                         UnauthorizedAccessException)
        {
            throw new HostException("cannot inspect plugin artifact file", exception);
        }

        long observed = 0;
        await using (var stream = new FileStream(
                         entry.FullPath,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.Read,
                         64 * 1024,
                         FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var openedLength = stream.Length;
            if (openedLength != entry.Length)
            {
                throw new HostException("plugin artifact file changed before it was read");
            }
            var buffer = GC.AllocateUninitializedArray<byte>(64 * 1024);
            while (true)
            {
                var count = await stream.ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                if (count == 0)
                {
                    break;
                }
                observed = checked(observed + count);
                if (observed > entry.Length)
                {
                    throw new HostException("plugin artifact file grew while it was read");
                }
                hash.AppendData(buffer.AsSpan(0, count));
            }
        }
        if (observed != entry.Length)
        {
            throw new HostException("plugin artifact file changed while it was read");
        }

        var after = new FileInfo(entry.FullPath);
        after.Refresh();
        if (!after.Exists || after.Length != entry.Length ||
            (after.Attributes & (FileAttributes.Directory |
                                 FileAttributes.ReparsePoint)) != 0)
        {
            throw new HostException("plugin artifact file changed while it was hashed");
        }
    }

    private static byte[] EncodePath(string value)
    {
        try
        {
            return StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new HostException("plugin artifact contains a non-UTF-8 path", exception);
        }
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, byte[] value)
    {
        var length = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(length, checked((ulong)value.LongLength));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static int CompareBytes(byte[] left, byte[] right)
    {
        var common = Math.Min(left.Length, right.Length);
        for (var index = 0; index < common; index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }
        return left.Length.CompareTo(right.Length);
    }

    private sealed record ArtifactEntry(
        string FullPath,
        byte[] RelativePathUtf8,
        bool IsDirectory,
        long Length);

    private sealed class ArtifactEntryComparer : IComparer<ArtifactEntry>
    {
        internal static ArtifactEntryComparer Instance { get; } = new();

        public int Compare(ArtifactEntry? left, ArtifactEntry? right)
        {
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(right);
            return CompareBytes(left.RelativePathUtf8, right.RelativePathUtf8);
        }
    }

    private sealed class TraversalCounters
    {
        internal long VisitedEntries { get; set; }
        internal long Files { get; set; }
        internal long Entries { get; set; }
        internal long TotalBytes { get; set; }
    }
}
