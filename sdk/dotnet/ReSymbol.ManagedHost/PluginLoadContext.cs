using System.Reflection;
using System.Runtime.Loader;
using ReSymbol.PluginSdk;

namespace ReSymbol.ManagedHost;

internal sealed class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblySnapshot snapshot;
    private readonly HashSet<string> trustedPlatformAssemblies;

    internal PluginLoadContext(AssemblySnapshot snapshot)
        : base($"ReSymbol.ManagedPlugin.{Guid.NewGuid():N}", isCollectible: true)
    {
        this.snapshot = snapshot;
        trustedPlatformAssemblies = TrustedPlatformAssemblyNames();
        var sdkSimpleName = typeof(IReSymbolPlugin).Assembly.GetName().Name
            ?? throw new HostException("managed SDK assembly has no simple name");
        snapshot.RejectReservedSimpleNames(trustedPlatformAssemblies, sdkSimpleName);
    }

    internal Assembly LoadEntryAssembly()
    {
        var entry = snapshot.Entry();
        return LoadSnapshot(entry);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        var simpleName = assemblyName.Name;
        if (string.IsNullOrEmpty(simpleName))
        {
            throw new HostException("plugin requested an assembly without a simple name");
        }
        if (string.Equals(simpleName, typeof(IReSymbolPlugin).Assembly.GetName().Name,
                StringComparison.OrdinalIgnoreCase))
        {
            ValidateSdkReference(assemblyName);
            return typeof(IReSymbolPlugin).Assembly;
        }
        if (trustedPlatformAssemblies.Contains(simpleName))
        {
            return null;
        }
        var dependency = snapshot.ResolveAssembly(assemblyName)
            ?? throw new HostException(
                $"managed dependency is absent from the host-owned closure: {simpleName}");
        return LoadSnapshot(dependency);
    }

    protected override nint LoadUnmanagedDll(string unmanagedDllName) =>
        throw new DllNotFoundException(
            $"unmanaged dependency loading is disabled in the managed plugin context: " +
            unmanagedDllName);

    private Assembly LoadSnapshot(SnapshotFile file)
    {
        using var stream = new MemoryStream(file.Bytes, writable: false);
        return LoadFromStream(stream);
    }

    internal static void ValidateSdkReference(AssemblyName requested)
    {
        var provided = typeof(IReSymbolPlugin).Assembly.GetName();
        if (!string.Equals(requested.Name, provided.Name, StringComparison.OrdinalIgnoreCase) ||
            requested.Version != provided.Version ||
            !string.Equals(
                requested.CultureName ?? string.Empty,
                provided.CultureName ?? string.Empty,
                StringComparison.OrdinalIgnoreCase) ||
            !TokensEqual(requested.GetPublicKeyToken(), provided.GetPublicKeyToken()) ||
            requested.ContentType != provided.ContentType)
        {
            throw new FileLoadException(
                $"plugin requires {requested.FullName}, but this managed host provides " +
                provided.FullName);
        }
    }

    private static bool TokensEqual(byte[]? left, byte[]? right)
    {
        left ??= [];
        right ??= [];
        return left.AsSpan().SequenceEqual(right);
    }

    private static HashSet<string> TrustedPlatformAssemblyNames()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") is not string paths)
        {
            return result;
        }
        foreach (var path in paths.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            if (!string.IsNullOrEmpty(name))
            {
                result.Add(name);
            }
        }
        return result;
    }
}
