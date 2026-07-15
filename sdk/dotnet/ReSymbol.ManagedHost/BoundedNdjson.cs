using System.Text.Json;

namespace ReSymbol.ManagedHost;

internal sealed class BoundedNdjsonReader
{
    private readonly Stream stream;
    private readonly byte[] buffer = new byte[8192];
    private int offset;
    private int count;

    internal BoundedNdjsonReader(Stream stream)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    internal async ValueTask<byte[]> ReadLineAsync(
        string description,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        using var line = new MemoryStream(Math.Min(limit, 8192));
        while (true)
        {
            if (offset == count)
            {
                count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                offset = 0;
                if (count == 0)
                {
                    if (line.Length == 0)
                    {
                        throw new HostException($"missing {description}");
                    }
                    throw new HostException($"{description} is not newline terminated");
                }
            }

            var newline = Array.IndexOf(buffer, (byte)'\n', offset, count - offset);
            var end = newline >= 0 ? newline : count;
            var chunkLength = end - offset;
            if (line.Length + chunkLength > limit)
            {
                throw new HostException($"{description} exceeds the {limit}-byte limit");
            }
            line.Write(buffer, offset, chunkLength);
            offset = newline >= 0 ? newline + 1 : count;

            if (newline < 0)
            {
                continue;
            }

            var bytes = line.ToArray();
            if (bytes.Length > 0 && bytes[^1] == (byte)'\r')
            {
                Array.Resize(ref bytes, bytes.Length - 1);
            }
            if (bytes.Length == 0)
            {
                throw new HostException($"{description} must not be empty");
            }
            return bytes;
        }
    }

    internal async ValueTask RequireEndAsync(CancellationToken cancellationToken = default)
    {
        if (offset != count)
        {
            throw new HostException("managed-host input contains trailing data");
        }
        var read = await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken)
            .ConfigureAwait(false);
        if (read != 0)
        {
            throw new HostException("managed-host input contains trailing data");
        }
    }
}

internal static class StrictJson
{
    internal static T Decode<T>(ReadOnlySpan<byte> bytes, string description)
    {
        try
        {
            var owned = bytes.ToArray();
            using var document = JsonDocument.Parse(owned, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = ProtocolConstants.JsonOptions.MaxDepth,
            });
            RejectDuplicateProperties(document.RootElement, description);
            return JsonSerializer.Deserialize<T>(owned, ProtocolConstants.JsonOptions)
                ?? throw new HostException($"{description} decoded to null");
        }
        catch (HostException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new HostException($"invalid {description} JSON", exception);
        }
    }

    private static void RejectDuplicateProperties(JsonElement value, string description)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new HostException(
                        $"{description} contains duplicate property '{property.Name}'");
                }
                RejectDuplicateProperties(property.Value, description);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                RejectDuplicateProperties(item, description);
            }
        }
    }
}
