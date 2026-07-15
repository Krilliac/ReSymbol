using System.Text.Json;

namespace ReSymbol.ManagedHost;

internal static class WireOutput
{
    private const string FallbackRejectionMessage = "managed plugin request failed";
    private static readonly object Version = new
    {
        major = ProtocolConstants.Major,
        minor = ProtocolConstants.Minor,
    };

    internal static byte[] EncodeExecution(
        ManagedExecution execution,
        string requestId,
        int maxMessageBytes,
        int maxStdoutBytes)
    {
        using var output = new MemoryStream(Math.Min(maxStdoutBytes, 16 * 1024));
        var hello = EncodeHelloResult(execution.Descriptor, maxMessageBytes);
        AppendEncodedLine(
            output,
            hello,
            maxStdoutBytes);

        if (execution.Rejection is not null)
        {
            if (execution.Events.Count != 0)
            {
                throw new HostException(
                    "rejected managed execution retained transactional events");
            }
            AppendEncodedLine(
                output,
                EncodeBoundedRejectionResponse(
                    requestId,
                    execution.Rejection,
                    maxMessageBytes,
                    maxStdoutBytes - hello.Length - 2),
                maxStdoutBytes);
            return output.ToArray();
        }

        foreach (var pluginEvent in execution.Events)
        {
            AppendEncodedEvent(output, pluginEvent, maxMessageBytes, maxStdoutBytes);
        }

        AppendEncodedLine(
            output,
            EncodeTerminalResponse(requestId, rejection: null, maxMessageBytes),
            maxStdoutBytes);
        return output.ToArray();
    }

    // Validate every mandatory terminal shape while input is still entirely
    // host-owned and before the plugin-attribution marker is published.
    internal static void ValidateMandatoryOutput(
        ExpectedPlugin expected,
        string requestId,
        int maxMessageBytes,
        int maxStdoutBytes)
    {
        var hello = EncodeHelloResult(expected, maxMessageBytes);
        var success = EncodeTerminalResponse(requestId, rejection: null, maxMessageBytes);
        EnsureMandatoryAggregate(hello, success, maxStdoutBytes);
        var rejection = EncodeTerminalResponse(
            requestId,
            new PluginRejection("internal", FallbackRejectionMessage),
            maxMessageBytes);
        EnsureMandatoryAggregate(hello, rejection, maxStdoutBytes);
    }

    // Buffered events commit only when execution succeeds. Reserve the exact
    // canonical hello and successful terminal response that will surround a
    // committed batch; rejected executions discard every event before output.
    internal static int CommittedEventByteBudget(
        ExpectedPlugin expected,
        string requestId,
        int maxMessageBytes,
        int maxStdoutBytes)
    {
        ValidateMandatoryOutput(expected, requestId, maxMessageBytes, maxStdoutBytes);
        var hello = EncodeHelloResult(expected, maxMessageBytes);
        var response = EncodeTerminalResponse(
            requestId,
            rejection: null,
            maxMessageBytes);
        var mandatoryBytes = MandatoryBytes(hello, response);
        return checked(maxStdoutBytes - (int)mandatoryBytes);
    }

    internal static BufferedEvent EncodeEvent(
        string method,
        object payload,
        int maxMessageBytes)
    {
        byte[] encoded;
        try
        {
            encoded = JsonSerializer.SerializeToUtf8Bytes(
                EventEnvelope(method, payload),
                ProtocolConstants.JsonOptions);
        }
        catch (Exception exception) when (
            exception is JsonException or InvalidOperationException or NotSupportedException)
        {
            throw new HostInvalidArgumentException(
                "managed plugin event could not be serialized",
                exception);
        }
        if (encoded.Length > maxMessageBytes)
        {
            throw new HostResourceLimitException(
                "managed plugin output message limit exceeded");
        }
        return new BufferedEvent(method, encoded);
    }

    private static object EventEnvelope(string method, object payload) => new
    {
        protocol = ProtocolConstants.PluginWire,
        version = Version,
        kind = "event",
        direction = "plugin-to-host",
        method,
        payload,
    };

    private static byte[] EncodeHelloResult(
        PluginDescriptorModel descriptor,
        int maxMessageBytes) => EncodeHelloResult(
            descriptor.Id,
            descriptor.Name,
            descriptor.Version,
            descriptor.Capabilities,
            descriptor.RequestedPermissions,
            maxMessageBytes);

    private static byte[] EncodeHelloResult(
        ExpectedPlugin descriptor,
        int maxMessageBytes) => EncodeHelloResult(
            descriptor.Id,
            descriptor.Name,
            descriptor.Version,
            descriptor.Capabilities,
            descriptor.RequestedPermissions,
            maxMessageBytes);

    private static byte[] EncodeHelloResult(
        string id,
        string name,
        string version,
        IReadOnlyList<string> capabilities,
        IReadOnlyList<string> requestedPermissions,
        int maxMessageBytes) => EncodeLine(new
        {
            protocol = ProtocolConstants.PluginWire,
            version = Version,
            kind = "hello-result",
            descriptor = new
            {
                id,
                name,
                version,
                capabilities = CanonicalIdentifiers(capabilities),
                requested_permissions = CanonicalIdentifiers(requestedPermissions),
                isolation = new { mode = "process", required = true },
            },
        }, maxMessageBytes);

    private static byte[] EncodeTerminalResponse(
        string requestId,
        PluginRejection? rejection,
        int maxMessageBytes) => EncodeLine(
            TerminalResponse(requestId, rejection),
            maxMessageBytes);

    private static object TerminalResponse(
        string requestId,
        PluginRejection? rejection)
    {
        // The protocol requires exactly one of result/error. Dictionary
        // insertion order is deliberate and covered by byte-level tests.
        var response = new Dictionary<string, object?>
        {
            ["protocol"] = ProtocolConstants.PluginWire,
            ["version"] = Version,
            ["kind"] = "response",
            ["direction"] = "plugin-to-host",
            ["id"] = requestId,
            ["ok"] = rejection is null,
        };
        if (rejection is null)
        {
            response["result"] = new { accepted = true };
        }
        else
        {
            response["error"] = new
            {
                code = rejection.Code,
                message = rejection.Message,
            };
        }
        return response;
    }

    private static byte[] EncodeBoundedRejectionResponse(
        string requestId,
        PluginRejection rejection,
        int maxMessageBytes,
        int availableAggregateBytes)
    {
        var code = CanonicalRejectionCode(rejection.Code);
        if (rejection.Message is not null)
        {
            var requested = SerializeLine(TerminalResponse(
                requestId,
                new PluginRejection(code, rejection.Message)));
            if (Fits(requested, maxMessageBytes, availableAggregateBytes))
            {
                return requested;
            }
        }

        var bounded = SerializeLine(TerminalResponse(
            requestId,
            new PluginRejection(code, FallbackRejectionMessage)));
        if (Fits(bounded, maxMessageBytes, availableAggregateBytes))
        {
            return bounded;
        }

        var fallback = SerializeLine(TerminalResponse(
            requestId,
            new PluginRejection("internal", FallbackRejectionMessage)));
        if (Fits(fallback, maxMessageBytes, availableAggregateBytes))
        {
            return fallback;
        }
        throw new HostException(
            "managed-host mandatory rejection output exceeds negotiated limits");
    }

    private static string CanonicalRejectionCode(string? code) => code switch
    {
        "cancelled" or
        "internal" or
        "invalid-argument" or
        "permission-denied" or
        "resource-limit" or
        "unavailable" => code,
        _ => "internal",
    };

    private static bool Fits(byte[] encoded, int maxMessageBytes, int availableAggregateBytes) =>
        encoded.Length <= maxMessageBytes && encoded.Length <= availableAggregateBytes;

    private static long MandatoryBytes(byte[] hello, byte[] response) =>
        checked((long)hello.Length + response.Length + 2L);

    private static void EnsureMandatoryAggregate(
        byte[] hello,
        byte[] response,
        int maxStdoutBytes)
    {
        if (MandatoryBytes(hello, response) > maxStdoutBytes)
        {
            throw new HostException(
                "managed-host mandatory output exceeds the aggregate stdout limit");
        }
    }

    private static string[] CanonicalIdentifiers(IReadOnlyList<string> values) =>
        values.OrderBy(static value => value, StringComparer.Ordinal).ToArray();

    private static void AppendEncodedEvent(
        MemoryStream output,
        BufferedEvent pluginEvent,
        int maxMessageBytes,
        int maxStdoutBytes)
    {
        if (pluginEvent.EncodedLineLength > maxMessageBytes)
        {
            throw new HostException(
                "buffered managed event exceeds the negotiated message limit");
        }
        if (output.Length + pluginEvent.EncodedLineLength + 1 > maxStdoutBytes)
        {
            throw new HostException("managed-host aggregate stdout limit exceeded");
        }
        output.Write(pluginEvent.EncodedLine);
        output.WriteByte((byte)'\n');
    }

    private static void AppendEncodedLine(
        MemoryStream output,
        byte[] encoded,
        int maxStdoutBytes)
    {
        if (output.Length + encoded.Length + 1 > maxStdoutBytes)
        {
            throw new HostException("managed-host aggregate stdout limit exceeded");
        }
        output.Write(encoded);
        output.WriteByte((byte)'\n');
    }

    private static byte[] EncodeLine(object value, int maxMessageBytes)
    {
        var encoded = SerializeLine(value);
        if (encoded.Length > maxMessageBytes)
        {
            throw new HostException("managed-host output message limit exceeded");
        }
        return encoded;
    }

    private static byte[] SerializeLine(object value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, ProtocolConstants.JsonOptions);
}
