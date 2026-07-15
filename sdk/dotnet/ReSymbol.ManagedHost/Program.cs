using System.Reflection;
using ReSymbol.ManagedHost;

if (args is ["--version"])
{
    var informationalVersion = typeof(HostRunner).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException(
            "managed host assembly has no informational version");
    Console.WriteLine($"resymbol-managed-host {informationalVersion}");
    return 0;
}

var exitCode = await HostRunner.RunProcessAsync(args, Console.OpenStandardInput(),
    Console.OpenStandardOutput(), Console.Error);
Console.Out.Flush();
Console.Error.Flush();

// A plugin can leave foreground threads or finalizers behind. This executable is
// deliberately single-use, so process teardown is the isolation/unload boundary.
Environment.Exit(exitCode);
return exitCode;
