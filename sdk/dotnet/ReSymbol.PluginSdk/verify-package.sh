#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 PACKAGE.nupkg EXPECTED_VERSION" >&2
  exit 2
fi

package="$(realpath "$1")"
expected_version="$2"
if [[ ! -f "$package" ]]; then
  echo "managed SDK package does not exist: $package" >&2
  exit 1
fi

mapfile -t entries < <(unzip -Z1 "$package")
for required in \
  README.md \
  ref/net8.0/ReSymbol.PluginSdk.dll \
  ref/net8.0/ReSymbol.PluginSdk.xml; do
  if ! printf '%s\n' "${entries[@]}" | grep --fixed-strings --line-regexp --quiet "$required"; then
    echo "managed SDK package is missing $required" >&2
    exit 1
  fi
done

if printf '%s\n' "${entries[@]}" |
    grep --extended-regexp --ignore-case --quiet '^(lib|runtimes)/.*\.dll$'; then
  echo "managed SDK package unexpectedly contains a runtime assembly" >&2
  exit 1
fi

mapfile -t nuspecs < <(printf '%s\n' "${entries[@]}" | grep --extended-regexp '\.nuspec$')
if [[ "${#nuspecs[@]}" -ne 1 ]]; then
  echo "managed SDK package must contain exactly one nuspec" >&2
  exit 1
fi
actual_version="$(
  unzip -p "$package" "${nuspecs[0]}" |
    sed -n 's:.*<version>\([^<]*\)</version>.*:\1:p'
)"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "managed SDK package version $actual_version does not match $expected_version" >&2
  exit 1
fi

probe="$(mktemp -d -t resymbol-sdk-package-probe.XXXXXXXX)"
trap 'rm -rf "$probe"' EXIT
cat >"$probe/Probe.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="ReSymbol.PluginSdk" Version="$expected_version" />
  </ItemGroup>
</Project>
EOF
cat >"$probe/Probe.cs" <<'EOF'
using ReSymbol.PluginSdk;

namespace PackageProbe;

public static class Probe
{
    public static System.Type Contract => typeof(IReSymbolPlugin);
}
EOF

export NUGET_PACKAGES="$probe/packages"
mkdir -p "$NUGET_PACKAGES"
dotnet restore "$probe/Probe.csproj" \
  --source "$(dirname "$package")" \
  --nologo
dotnet build "$probe/Probe.csproj" \
  --configuration Release \
  --no-restore \
  --nologo \
  --verbosity minimal \
  -warnaserror \
  -m:1

if [[ -e "$probe/bin/Release/net8.0/ReSymbol.PluginSdk.dll" ]]; then
  echo "compile-only managed SDK was copied into consumer runtime output" >&2
  exit 1
fi
