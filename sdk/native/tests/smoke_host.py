#!/usr/bin/env python3
"""Compile C/C++ native fixtures and exercise the disposable native host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile


PLUGIN_ID = "dev.resymbol.native-fixture"
PLUGIN_NAME = "Native host fixture"
PLUGIN_VERSION = "0.1.0"
FINGERPRINT_DOMAIN = b"resymbol.plugin-artifact-fingerprint\0v1\0"
LOAD_ATTEMPTED_MARKER = b"@resymbol-native-host/load-attempted/v1@\n"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument(
        "--resymbol",
        type=Path,
        help="also exercise trust, analyze, package, and inspect through this CLI",
    )
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cxx", default="c++")
    parser.add_argument(
        "--compiler-style",
        choices=("unix", "msvc"),
        default="msvc" if os.name == "nt" else "unix",
    )
    return parser.parse_args()


def run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def run_captured(command: list[str], *, timeout: int = 90) -> bytes:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            + completed.stderr.decode("utf-8", errors="replace")
        )
    if completed.stderr:
        raise RuntimeError(
            f"command wrote unexpected stderr: {' '.join(command)}\n"
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout


def compile_fixture(
    compiler: str,
    language: str,
    style: str,
    source: Path,
    include: Path,
    plugin_root: Path,
) -> Path:
    if os.name == "nt":
        suffix = ".dll"
    elif sys.platform == "darwin":
        suffix = ".dylib"
    else:
        suffix = ".so"
    library = plugin_root / f"native_fixture_{language}{suffix}"

    if style == "msvc":
        command = [
            compiler,
            "/nologo",
            "/LD",
            "/W4",
            "/WX",
            "/TC" if language == "c" else "/TP",
        ]
        if language == "c":
            command.append("/std:c11")
        command.extend(
            [
                f"/I{include}",
                str(source),
                f"/Fe:{library}",
                "/link",
                "/NOLOGO",
                "/INCREMENTAL:NO",
            ]
        )
    else:
        command = [compiler]
        if language == "c":
            command.append("-std=c11")
        else:
            command.extend(["-x", "c++", "-std=c++11"])
        command.extend(
            [
                "-dynamiclib" if sys.platform == "darwin" else "-shared",
                "-fPIC",
                "-fvisibility=hidden",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-I",
                str(include),
                str(source),
                "-o",
                str(library),
            ]
        )

    run_checked(command, cwd=plugin_root)
    if not library.is_file():
        raise RuntimeError(f"compiler did not create {library}")

    # MSVC writes link-time sidecars into the working directory. They are not
    # runtime dependencies and keeping them would make the smoke fingerprint
    # depend on compiler defaults.
    for child in plugin_root.iterdir():
        if child != library:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    return library


def write_manifest(plugin_root: Path, entrypoint: str) -> None:
    manifest = f'''manifest_version = 1
id = "{PLUGIN_ID}"
name = "{PLUGIN_NAME}"
version = "{PLUGIN_VERSION}"
api = "^0.1.0"
capabilities = ["analyzer.binary"]
permissions = ["binary.read", "claims.submit"]

[runtime]
kind = "native"
entrypoint = "{entrypoint}"
isolation = "out-of-process"
'''
    (plugin_root / "plugin.toml").write_text(manifest, encoding="utf-8", newline="\n")


def artifact_fingerprint(plugin_root: Path) -> str:
    records: list[tuple[bytes, Path, bool]] = []
    for path in plugin_root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"fixture unexpectedly contains a symlink: {path}")
        relative = path.relative_to(plugin_root).as_posix().encode("utf-8")
        if path.is_dir():
            records.append((relative, path, True))
        elif path.is_file() and relative != b"plugin.disabled":
            records.append((relative, path, False))
        else:
            raise RuntimeError(f"fixture contains an unsupported entry: {path}")

    digest = hashlib.sha256()
    digest.update(FINGERPRINT_DOMAIN)
    for relative, path, is_directory in sorted(records, key=lambda record: record[0]):
        digest.update(b"d" if is_directory else b"f")
        digest.update(struct.pack("<Q", len(relative)))
        digest.update(relative)
        if not is_directory:
            contents = path.read_bytes()
            digest.update(struct.pack("<Q", len(contents)))
            digest.update(contents)
    return digest.hexdigest()


def put_u16(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buffer, offset, value)


def put_u32(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buffer, offset, value)


def put_u64(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buffer, offset, value)


def write_pe_fixture(path: Path) -> dict[str, object]:
    pe_offset = 0x80
    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20
    section_offset = optional_offset + 0xF0
    raw_offset = 0x200
    section_rva = 0x1000
    image_base = 0x0000000140000000

    contents = bytearray(0x400)
    contents[0:2] = b"MZ"
    put_u32(contents, 0x3C, pe_offset)
    contents[pe_offset : pe_offset + 4] = b"PE\0\0"
    put_u16(contents, coff_offset, 0x8664)
    put_u16(contents, coff_offset + 2, 1)
    put_u16(contents, coff_offset + 16, 0xF0)
    put_u16(contents, coff_offset + 18, 0x2022)
    put_u16(contents, optional_offset, 0x020B)
    put_u32(contents, optional_offset + 16, section_rva)
    put_u64(contents, optional_offset + 24, image_base)
    put_u32(contents, optional_offset + 32, 0x1000)
    put_u32(contents, optional_offset + 36, 0x200)
    put_u32(contents, optional_offset + 56, 0x2000)
    put_u32(contents, optional_offset + 60, raw_offset)
    put_u32(contents, optional_offset + 108, 16)
    contents[section_offset : section_offset + 6] = b".text\0"
    put_u32(contents, section_offset + 8, 0x200)
    put_u32(contents, section_offset + 12, section_rva)
    put_u32(contents, section_offset + 16, 0x200)
    put_u32(contents, section_offset + 20, raw_offset)
    put_u32(contents, section_offset + 36, 0x60000020)
    path.write_bytes(contents)

    identity: dict[str, object] = {
        "id": hashlib.sha256(contents).hexdigest(),
        "size": len(contents),
        "format": "pe",
        "architecture": "x86_64",
        "image_base": image_base,
    }
    return identity


def invoke_host(host: Path, plugin_root: Path, binary: Path, identity: dict[str, object]) -> None:
    bootstrap = {
        "protocol": "resymbol.native-host",
        "version": {"major": 1, "minor": 0},
        "expected_artifact_sha256": artifact_fingerprint(plugin_root),
        "output_limits": {
            "max_messages": 4096,
            "max_stdout_bytes": 8 * 1024 * 1024,
        },
        "binary": identity,
        "image": {
            "size_of_headers": 0x200,
            "size_of_image": 0x2000,
            "sections": [
                {
                    "virtual_address": 0x1000,
                    "virtual_size": 0x200,
                    "raw_data_offset": 0x200,
                    "raw_data_size": 0x200,
                }
            ],
        },
    }
    hello = {
        "protocol": "resymbol.plugin-wire",
        "version": {"major": 1, "minor": 0},
        "kind": "hello",
        "session_id": "native-host-ci",
        "plugin_id": PLUGIN_ID,
        "granted_permissions": ["binary.read", "claims.submit"],
        "limits": {
            "max_message_bytes": 1024 * 1024,
            "max_memory_bytes": 256 * 1024 * 1024,
            "request_timeout_ms": 30_000,
        },
        "isolation": {"mode": "process", "required": True},
    }
    request = {
        "protocol": "resymbol.plugin-wire",
        "version": {"major": 1, "minor": 0},
        "kind": "request",
        "direction": "host-to-plugin",
        "id": "native-host-request",
        "method": "analyze",
        "payload": {"binary": identity},
    }
    input_bytes = b"".join(
        json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        for message in (bootstrap, hello, request)
    )

    completed = subprocess.run(
        [str(host), "--plugin-root", str(plugin_root), "--binary", str(binary)],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=45,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"native host failed with {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    if completed.stderr != LOAD_ATTEMPTED_MARKER:
        raise RuntimeError(
            "native host did not emit exactly the expected load-attempted marker: "
            + completed.stderr.decode("utf-8", errors="replace")
        )

    lines = completed.stdout.splitlines()
    messages = [json.loads(line) for line in lines]
    if len(messages) != 4:
        raise RuntimeError(f"expected four native-host messages, got {len(messages)}")
    descriptor = messages[0].get("descriptor", {})
    if messages[0].get("kind") != "hello-result" or descriptor.get("id") != PLUGIN_ID:
        raise RuntimeError("native host did not return the fixture descriptor")
    events = [message for message in messages if message.get("kind") == "event"]
    methods = {message.get("method") for message in events}
    if methods != {"log", "claim"}:
        raise RuntimeError(f"native host returned unexpected event methods: {methods}")
    claims = [message["payload"] for message in events if message.get("method") == "claim"]
    if len(claims) != 1 or claims[0].get("claim", {}).get("name") != "native_fixture":
        raise RuntimeError("native host did not preserve the fixture claim")
    response = messages[-1]
    if response.get("kind") != "response" or not response.get("ok"):
        raise RuntimeError(f"native host returned a rejected response: {response}")


def invoke_cli(
    resymbol: Path,
    compiler: str,
    compiler_style: str,
    source: Path,
    include: Path,
    root: Path,
    binary: Path,
    identity: dict[str, object],
) -> None:
    plugin_directory = root / "cli-plugins"
    plugin_root = plugin_directory / "native-fixture"
    plugin_root.mkdir(parents=True)
    library = compile_fixture(
        compiler,
        "c",
        compiler_style,
        source,
        include,
        plugin_root,
    )
    write_manifest(plugin_root, library.name)
    fingerprint = artifact_fingerprint(plugin_root)

    trust_output = run_captured(
        [
            str(resymbol),
            "--plugin-dir",
            str(plugin_directory),
            "plugin",
            "trust",
            PLUGIN_ID,
            "--fingerprint",
            fingerprint,
        ]
    ).decode("utf-8")
    if fingerprint not in trust_output or PLUGIN_ID not in trust_output:
        raise RuntimeError("CLI trust output did not identify the exact native artifact")

    package = root / "native-cli.resym"
    analyze_output = run_captured(
        [
            str(resymbol),
            "--plugin-dir",
            str(plugin_directory),
            "analyze",
            str(binary),
            "--output",
            str(package),
            "--plugin",
            PLUGIN_ID,
            "--strict-plugins",
        ],
        timeout=120,
    ).decode("utf-8")
    if f"plugin {PLUGIN_ID}: succeeded" not in analyze_output:
        raise RuntimeError("CLI analysis did not report a successful native plugin run")
    if not package.is_file():
        raise RuntimeError("CLI analysis did not create the expected package")

    inspected = json.loads(
        run_captured([str(resymbol), "inspect", str(package), "--json"]).decode("utf-8")
    )
    if inspected.get("binary_sha256") != identity["id"]:
        raise RuntimeError("inspected package is not bound to the exact fixture binary")
    payload = inspected.get("payload", {})
    runs = payload.get("plugin_runs", [])
    matching_runs = [run for run in runs if run.get("plugin_id") == PLUGIN_ID]
    if len(matching_runs) != 1:
        raise RuntimeError("inspected package does not contain exactly one native fixture run")
    run = matching_runs[0]
    if (
        run.get("status") != "succeeded"
        or run.get("artifact_sha256") != fingerprint
        or run.get("accepted_claim_count") != 1
    ):
        raise RuntimeError(f"inspected native fixture run is inconsistent: {run}")

    claims = payload.get("plugin_claims", [])
    matching_claims = [
        claim
        for claim in claims
        if claim.get("assertion", {}).get("kind") == "name"
        and claim.get("assertion", {}).get("name") == "native_fixture"
    ]
    if len(matching_claims) != 1:
        raise RuntimeError("inspected package does not contain the native fixture name claim")
    producer = matching_claims[0].get("provenance", {}).get("producer", {})
    if producer.get("kind") != "plugin" or producer.get("id") != PLUGIN_ID:
        raise RuntimeError("native fixture claim lost its plugin provenance")
    print("native CLI trust/analyze/inspect fixture passed", flush=True)


def main() -> int:
    arguments = parse_arguments()
    repository = Path(__file__).resolve().parents[3]
    host = arguments.host.resolve()
    if not host.is_file():
        raise RuntimeError(f"native host does not exist: {host}")
    resymbol = arguments.resymbol.resolve() if arguments.resymbol is not None else None
    if resymbol is not None and not resymbol.is_file():
        raise RuntimeError(f"ReSymbol CLI does not exist: {resymbol}")
    source = repository / "crates/resymbol-native-host/tests/fixtures/native_fixture.c"
    include = repository / "sdk/native/include"

    with tempfile.TemporaryDirectory(prefix="resymbol-native-smoke-") as temporary:
        root = Path(temporary)
        binary = root / "fixture.exe"
        identity = write_pe_fixture(binary)
        for language, compiler in (("c", arguments.cc), ("cpp", arguments.cxx)):
            plugin_root = root / f"plugin-{language}"
            plugin_root.mkdir()
            library = compile_fixture(
                compiler,
                "c" if language == "c" else "cpp",
                arguments.compiler_style,
                source,
                include,
                plugin_root,
            )
            write_manifest(plugin_root, library.name)
            invoke_host(host, plugin_root, binary, identity)
            print(f"native {language} fixture passed", flush=True)
        if resymbol is not None:
            invoke_cli(
                resymbol,
                arguments.cc,
                arguments.compiler_style,
                source,
                include,
                root,
                binary,
                identity,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"native-host smoke failure: {error}", file=sys.stderr)
        raise SystemExit(1) from error
