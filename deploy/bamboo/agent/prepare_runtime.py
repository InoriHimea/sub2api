#!/usr/bin/env python3
"""Prepare an immutable runtime and vendor classpath cache; never start an Agent."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import zipfile
import zlib

RUNTIME = "generic/lib/bamboo-agent-bootstrap-jar-with-dependencies.jar"
VERSION = "META-INF/maven/com.atlassian.bamboo/bamboo-agent-bootstrap/pom.properties"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def prepare(installer, installer_sha256, runtime_sha256, version, output):
    if not re.fullmatch(r"[0-9a-f]{64}", installer_sha256) or not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
        raise ValueError("Expected lowercase SHA256 pins")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[-.][A-Za-z0-9]+)*", version):
        raise ValueError("Invalid version")
    if digest(installer) != installer_sha256:
        raise ValueError("Installer SHA256 mismatch")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; never overwrite a prepared generation")
    with zipfile.ZipFile(installer) as outer, tempfile.TemporaryFile() as cache:
        runtime = outer.read(RUNTIME)
        if hashlib.sha256(runtime).hexdigest() != runtime_sha256:
            raise ValueError("Runtime SHA256 mismatch")
        with tempfile.TemporaryFile() as runtime_file:
            runtime_file.write(runtime)
            runtime_file.seek(0)
            with zipfile.ZipFile(runtime_file) as jar:
                properties = dict(line.split("=", 1) for line in jar.read(VERSION).decode().splitlines()
                                  if "=" in line and not line.startswith("#"))
                if properties.get("version") != version:
                    raise ValueError("Embedded runtime version mismatch")
        with outer.open("classpath.zip") as source:
            shutil.copyfileobj(source, cache, 1024 * 1024)
        cache.seek(0)
        with zipfile.ZipFile(cache) as payload:
            entries = [entry for entry in payload.infolist() if not entry.is_dir()]
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or len(names) > 3000:
                raise ValueError("Duplicate or excessive classpath entries")
            if sum(entry.file_size for entry in entries) > 2 * 1024 ** 3:
                raise ValueError("Classpath payload exceeds 2 GiB")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or len(path.parts) != 1 or name in (".", "..") or "\\" in name or ":" in name:
                    raise ValueError("Unsafe classpath entry")
            manifest = {}
            for line in payload.read("MANIFEST.DAT").decode().splitlines():
                fields = line.split("\t")
                if len(fields) != 3 or fields[0] != "+" or fields[1] in manifest or not re.fullmatch(r"[0-9a-f]{1,8}", fields[2]):
                    raise ValueError("Invalid vendor classpath manifest")
                manifest[fields[1]] = int(fields[2], 16)
            if set(manifest) != set(names) - {"MANIFEST.DAT"}:
                raise ValueError("Vendor manifest does not cover exact payload")
            # Exclusive generation reservation. A receipt is published only after all bytes verify.
            output.mkdir(mode=0o700)
            classpath = output / "home" / "classpath"
            classpath.mkdir(parents=True)
            runtime_name = "bamboo-agent-bootstrap-" + version + "-" + runtime_sha256 + ".jar"
            (output / runtime_name).write_bytes(runtime)
            files = {}
            for name, expected in sorted(manifest.items()):
                sha = hashlib.sha256()
                adler = 1
                length = 0
                with payload.open(name) as source, (classpath / name).open("xb") as target:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        target.write(block)
                        sha.update(block)
                        adler = zlib.adler32(block, adler)
                        length += len(block)
                if adler & 0xffffffff != expected:
                    raise ValueError("Vendor classpath checksum mismatch: " + name)
                files["classpath/" + name] = {"bytes": length, "adler32": format(expected, "x"), "sha256": sha.hexdigest()}
            receipt = {"schema": 1, "version": version, "installer_sha256": installer_sha256,
                       "runtime_sha256": runtime_sha256, "runtime_file": runtime_name,
                       "classpath": files, "starts_agent": False}
            pending = output / ".prepared.json.pending"
            with pending.open("x", encoding="utf-8") as stream:
                json.dump(receipt, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.link(pending, output / "prepared.json")
            pending.unlink()
            return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--installer-sha256", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.installer, args.installer_sha256, args.runtime_sha256, args.version, args.output)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps({"version": result["version"], "runtime_sha256": result["runtime_sha256"],
                      "classpath_files": len(result["classpath"]), "starts_agent": False}))


if __name__ == "__main__":
    main()
