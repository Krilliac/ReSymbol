using System.Reflection;
using System.Text;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal sealed record LoadedManagedPlugin(
    PluginLoadContext LoadContext,
    IReSymbolPlugin Plugin,
    PluginDescriptorModel Descriptor);

internal static class ManagedPluginLoader
{
    internal static LoadedManagedPlugin Load(AssemblySnapshot snapshot, HostInput input)
    {
        var context = new PluginLoadContext(snapshot);
        try
        {
            var assembly = context.LoadEntryAssembly();
            var candidate = FindCandidate(assembly);
            var attributeId = AttributeId(candidate);
            if (!string.Equals(attributeId, input.Hello.PluginId, StringComparison.Ordinal))
            {
                throw new HostException(
                    "plugin attribute identity does not match the host-owned hello");
            }
            var plugin = CreatePlugin(candidate);
            PluginMetadata metadata;
            try
            {
                metadata = plugin.Metadata
                    ?? throw new HostException("managed plugin metadata is null");
            }
            catch (HostException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw new PluginLifecycleException("metadata", exception);
            }
            var descriptor = ValidateMetadata(metadata, attributeId, input);
            return new LoadedManagedPlugin(context, plugin, descriptor);
        }
        catch
        {
            context.Unload();
            throw;
        }
    }

    private static Type FindCandidate(Assembly assembly)
    {
        Type[] types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException exception)
        {
            throw new HostException("managed entry assembly has unloadable types", exception);
        }

        var attributed = types.Where(type => type.CustomAttributes.Any(attribute =>
            attribute.AttributeType == typeof(ReSymbolPluginAttribute))).ToArray();
        if (attributed.Length != 1)
        {
            throw new HostException(
                "managed entry assembly must expose exactly one attributed plugin type");
        }
        var candidate = attributed[0];
        if (!candidate.IsClass || candidate.IsAbstract || !candidate.IsPublic ||
            !typeof(IReSymbolPlugin).IsAssignableFrom(candidate) ||
            candidate.GetConstructor(Type.EmptyTypes) is null)
        {
            throw new HostException(
                "managed plugin type must be public, concrete, implement IReSymbolPlugin, " +
                "and have a public parameterless constructor");
        }
        return candidate;
    }

    private static string AttributeId(Type candidate)
    {
        var data = candidate.CustomAttributes.Single(attribute =>
            attribute.AttributeType == typeof(ReSymbolPluginAttribute));
        if (data.ConstructorArguments is not [{ Value: string id }])
        {
            throw new HostException("managed plugin attribute has an invalid identifier");
        }
        HostInputReader.ValidateIdentifier(id, "plugin attribute id");
        return id;
    }

    private static IReSymbolPlugin CreatePlugin(Type candidate)
    {
        try
        {
            return (IReSymbolPlugin)(Activator.CreateInstance(candidate)
                ?? throw new HostException("managed plugin constructor returned null"));
        }
        catch (HostException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new PluginLifecycleException("construction", exception);
        }
    }

    private static PluginDescriptorModel ValidateMetadata(
        PluginMetadata metadata,
        string attributeId,
        HostInput input)
    {
        HostInputReader.ValidateIdentifier(metadata.Id, "plugin metadata id");
        if (metadata.Id != attributeId || metadata.Id != input.Hello.PluginId)
        {
            throw new HostException("managed plugin metadata identity does not match its package");
        }
        ValidateText(metadata.Name, "plugin name", 4096);
        ValidateText(metadata.Version, "plugin version", 128);
        var capabilities = ValidateIdentifiers(
            metadata.Capabilities, "plugin capability", 4096);
        var requested = ValidateIdentifiers(
            metadata.RequestedPermissions, "requested permission", 4096);
        var requestedSet = requested.ToHashSet(StringComparer.Ordinal);
        if (input.Hello.GrantedPermissions.Any(grant => !requestedSet.Contains(grant)))
        {
            throw new HostException(
                "hello grants a permission that managed plugin metadata did not request");
        }
        if (metadata.Isolation is not (PluginIsolationRequirement.OutOfProcess or
            PluginIsolationRequirement.TrustedInProcessAllowed))
        {
            throw new HostException("managed plugin declares an unknown isolation requirement");
        }
        var descriptor = new PluginDescriptorModel(
            metadata.Id,
            metadata.Name,
            metadata.Version,
            capabilities,
            requested);
        ValidateExpectedDescriptor(descriptor, input.Bootstrap.ExpectedPlugin);
        return descriptor;
    }

    private static void ValidateExpectedDescriptor(
        PluginDescriptorModel actual,
        ExpectedPlugin expected)
    {
        if (actual.Id != expected.Id || actual.Name != expected.Name ||
            actual.Version != expected.Version ||
            !actual.Capabilities.ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.Capabilities) ||
            !actual.RequestedPermissions.ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.RequestedPermissions))
        {
            throw new HostException(
                "managed plugin metadata does not match the host-owned manifest metadata");
        }
    }

    private static IReadOnlyList<string> ValidateIdentifiers(
        IReadOnlyList<string> values,
        string description,
        int maximum)
    {
        if (values is null || values.Count > maximum)
        {
            throw new HostException($"{description} list exceeds the {maximum}-entry limit");
        }
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            HostInputReader.ValidateIdentifier(value, description);
            if (!unique.Add(value))
            {
                throw new HostException($"{description} list contains a duplicate");
            }
        }
        return values.ToArray();
    }

    private static void ValidateText(string value, string description, int maximumBytes)
    {
        if (string.IsNullOrEmpty(value) || Encoding.UTF8.GetByteCount(value) > maximumBytes ||
            value.Any(char.IsControl))
        {
            throw new HostException($"invalid {description}");
        }
    }
}
