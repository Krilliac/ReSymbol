# ReSymbol.PluginSdk

`ReSymbol.PluginSdk` is the compile-time contract for out-of-process ReSymbol managed plugins.
It targets .NET 8 and contains plugin lifecycle, metadata, analysis, logging, binary-read, and
claim-submission APIs.

The package intentionally contains a reference assembly only. Do not copy
`ReSymbol.PluginSdk.dll` into a plugin package: the version-matched, app-local
`resymbol-managed-host` supplies the runtime contract and binds plugin references to it.

Download the `ReSymbol.PluginSdk.<version>.nupkg` asset that matches the ReSymbol release, add the
directory containing that file as a NuGet source alongside any sources your project already uses,
and reference it from a .NET 8 plugin project:

```xml
<ItemGroup>
  <PackageReference Include="ReSymbol.PluginSdk" Version="0.1.0-alpha.1" />
</ItemGroup>
```

For example, a repository-local `NuGet.Config` can add the downloaded-asset directory without
removing inherited package sources:

```xml
<configuration>
  <packageSources>
    <add key="resymbol-release" value="/path/to/downloaded/release-assets" />
  </packageSources>
</configuration>
```

After `dotnet restore`, the package supplies compile-time contracts without placing its SDK DLL in
your build output. Stage `plugin.toml`, your entry assembly, and your own private dependency DLLs.

`AnalysisRequest.BaseAnalysis` carries the detached canonical base analysis only when the plugin
was granted `symbols.read`; it is `null` without that permission. Request the permission in both the
manifest and `PluginMetadata` before depending on this input.

See the repository's `docs/plugin-system.md` and `examples/plugins/managed` for the complete
drop-in package layout and a working plugin.
