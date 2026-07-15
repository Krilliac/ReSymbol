using System.Reflection.PortableExecutable;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal sealed class ExactBinaryImage
{
    private readonly string path;
    private readonly byte[] bytes;
    private readonly PeImageMap image;

    private ExactBinaryImage(string path, byte[] bytes, PeImageMap image)
    {
        this.path = path;
        this.bytes = bytes;
        this.image = image;
    }

    internal static async ValueTask<ExactBinaryImage> OpenAsync(
        string path,
        ManagedHostBootstrap bootstrap,
        ulong availableSnapshotBytes,
        CancellationToken cancellationToken)
    {
        var maximum = (long)Math.Min(
            (ulong)ProtocolConstants.HardMaxBinaryBytes,
            availableSnapshotBytes);
        if (bootstrap.Binary.Size > (ulong)maximum)
        {
            throw new HostException(
                $"source binary exceeds the managed host's remaining " +
                $"{maximum}-byte verified-snapshot gate");
        }
        var bytes = await PathPolicy.ReadExactFileAsync(
            path,
            maximum,
            "exact source binary",
            cancellationToken).ConfigureAwait(false);
        if ((ulong)bytes.LongLength != bootstrap.Binary.Size ||
            !string.Equals(PathPolicy.Sha256Hex(bytes), bootstrap.Binary.Id,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new HostException(
                "source binary size or SHA-256 does not match the analysis identity");
        }
        VerifyPeMetadata(bytes, bootstrap.Binary, bootstrap.Image);
        return new ExactBinaryImage(path, bytes, bootstrap.Image);
    }

    internal ValueTask<int> ReadRvaAsync(
        ulong rva,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (destination.Length > ProtocolConstants.MaxBinaryReadCallBytes)
        {
            throw new HostException(
                $"binary.read call exceeds {ProtocolConstants.MaxBinaryReadCallBytes} bytes");
        }
        if (rva >= image.SizeOfImage)
        {
            throw new ArgumentOutOfRangeException(nameof(rva), "RVA lies outside the image");
        }
        if (destination.IsEmpty)
        {
            return ValueTask.FromResult(0);
        }

        if (rva < image.SizeOfHeaders)
        {
            return ValueTask.FromResult(CopyAvailable(
                checked((int)rva),
                checked((int)((ulong)image.SizeOfHeaders - rva)),
                destination.Span));
        }
        var section = image.Sections.FirstOrDefault(section =>
        {
            var start = (ulong)section.VirtualAddress;
            var size = (ulong)Math.Max(section.VirtualSize, section.RawDataSize);
            return rva >= start && rva < start + size;
        });
        if (section is null)
        {
            return ValueTask.FromResult(0);
        }
        var delta = rva - section.VirtualAddress;
        if (delta >= section.RawDataSize)
        {
            return ValueTask.FromResult(0);
        }
        var fileOffset = checked((int)((ulong)section.RawDataOffset + delta));
        var available = checked((int)((ulong)section.RawDataSize - delta));
        return ValueTask.FromResult(CopyAvailable(fileOffset, available, destination.Span));
    }

    internal async ValueTask VerifySourceAsync(CancellationToken cancellationToken)
    {
        await PathPolicy.VerifyExactSha256Async(
            path,
            bytes.LongLength,
            PathPolicy.Sha256Hex(bytes),
            "source binary post-run verification",
            cancellationToken).ConfigureAwait(false);
    }

    internal BinaryIdentity ToSdkIdentity(BinaryIdentityModel identity) => new(
        identity.Id,
        identity.FormatName,
        identity.Architecture,
        identity.Size,
        identity.ImageBase,
        image.SizeOfImage);

    private int CopyAvailable(int offset, int available, Span<byte> destination)
    {
        var count = Math.Min(Math.Min(available, destination.Length), bytes.Length - offset);
        if (count <= 0)
        {
            return 0;
        }
        bytes.AsSpan(offset, count).CopyTo(destination);
        return count;
    }

    private static void VerifyPeMetadata(
        byte[] bytes,
        BinaryIdentityModel identity,
        PeImageMap expected)
    {
        try
        {
            using var reader = new PEReader(new MemoryStream(bytes, writable: false));
            var headers = reader.PEHeaders;
            var pe = headers.PEHeader
                ?? throw new HostException("source binary has no PE optional header");
            if (headers.CoffHeader.Machine != Machine.Amd64 ||
                pe.Magic != PEMagic.PE32Plus ||
                pe.SectionAlignment <= 0 ||
                pe.FileAlignment <= 0 ||
                pe.NumberOfRvaAndSizes is < 0 or > 16 ||
                pe.ImageBase != identity.ImageBase ||
                pe.SizeOfHeaders != expected.SizeOfHeaders ||
                pe.SizeOfImage != expected.SizeOfImage ||
                headers.SectionHeaders.Length != expected.Sections.Count)
            {
                throw new HostException(
                    "PE header metadata does not match the host-owned image map");
            }
            for (var index = 0; index < headers.SectionHeaders.Length; index++)
            {
                var actual = headers.SectionHeaders[index];
                var wanted = expected.Sections[index];
                if ((uint)actual.VirtualAddress != wanted.VirtualAddress ||
                    (uint)actual.VirtualSize != wanted.VirtualSize ||
                    (uint)actual.PointerToRawData != wanted.RawDataOffset ||
                    (uint)actual.SizeOfRawData != wanted.RawDataSize)
                {
                    throw new HostException(
                        "PE section metadata does not match the host-owned image map");
                }
            }
        }
        catch (BadImageFormatException exception)
        {
            throw new HostException("source binary is not a valid PE32+ image", exception);
        }
    }
}
