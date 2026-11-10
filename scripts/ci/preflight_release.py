#!/usr/bin/env python3
"""Check release build prerequisites before frontend installation or test fixtures."""
import argparse
import json
import platform
import shutil
import sys

sys.dont_write_bytecode = True
import build_release as build


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if sys.version_info < (3, 9):
        raise build.BuildError("Python3.9 or newer is required")
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise build.BuildError("release builds require a Linux amd64 agent")
    missing_tools = [name for name in ("git", "go", "node", "npm", "docker", "tar", "sha256sum") if shutil.which(name) is None]
    if missing_tools:
        raise build.BuildError("required executables missing from PATH: %s" % ", ".join(missing_tools))

    required_files = [
        build.GO_MOD,
        build.REPO_ROOT / "frontend" / "package.json",
        build.REPO_ROOT / "frontend" / "pnpm-lock.yaml",
        build.SCRIPT_DIR / "qualify_release.py",
        build.DOCKERFILE_GORELEASER,
        build.ENTRYPOINT_SH,
    ] + [build.SCRIPT_DIR / name for name in build.DEPLOY_TOOL_FILES]
    missing_files = [str(path.relative_to(build.REPO_ROOT)) for path in required_files if not path.is_file()]
    if missing_files:
        raise build.BuildError("required source files missing: %s" % ", ".join(missing_files))

    build.verify_clean_source()
    tag, _, sha = build.resolve_tag_and_sha()
    node = build.run(["node", "--version"]).stdout.decode().strip()
    major, minor = (int(part) for part in node.lstrip("v").split(".")[:2])
    if major < 18 or (major == 18 and minor < 12) or major == 19:
        raise build.BuildError("Node18.12+ (18.x) or Node20+ is required by pnpm9/Vite5; found %s" % node)
    npm = build.run(["npm", "--version"]).stdout.decode().strip()
    if int(npm.split(".", 1)[0]) < 7:
        raise build.BuildError("npm7+ with npm exec is required; found %s" % npm)
    docker = build.run(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], timeout=30).stdout.decode().strip()
    if docker not in ("linux/x86_64", "linux/amd64"):
        raise build.BuildError("an accessible Linux amd64 Docker engine is required; found %s" % docker)
    compiler = build.verify_compiler()
    print(json.dumps({"schema": 1, "tag": tag, "sha": sha, "compiler": compiler,
                      "node": node, "npm": npm, "docker": docker}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except build.BuildError as exc:
        print("[preflight] FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
