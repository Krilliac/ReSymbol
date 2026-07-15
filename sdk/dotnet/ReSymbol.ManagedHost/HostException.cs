namespace ReSymbol.ManagedHost;

internal class HostException : Exception
{
    internal HostException(string message)
        : base(message)
    {
    }

    internal HostException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal interface IHostServiceFailure
{
    string Code { get; }
}

internal sealed class HostPermissionDeniedException : UnauthorizedAccessException,
    IHostServiceFailure
{
    internal HostPermissionDeniedException(string message)
        : base(message)
    {
    }

    public string Code => "permission-denied";
}

internal sealed class HostResourceLimitException : HostException, IHostServiceFailure
{
    internal HostResourceLimitException(string message)
        : base(message)
    {
    }

    public string Code => "resource-limit";
}

internal sealed class HostInvalidArgumentException : HostException, IHostServiceFailure
{
    internal HostInvalidArgumentException(string message)
        : base(message)
    {
    }

    internal HostInvalidArgumentException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public string Code => "invalid-argument";
}

internal sealed class HostServiceUnavailableException : HostException, IHostServiceFailure
{
    internal HostServiceUnavailableException(string message)
        : base(message)
    {
    }

    public string Code => "unavailable";
}

internal sealed class PluginLifecycleException : Exception
{
    internal PluginLifecycleException(string phase, Exception innerException)
        : base($"managed plugin {phase} failed", innerException)
    {
        Phase = phase;
    }

    internal string Phase { get; }
}
