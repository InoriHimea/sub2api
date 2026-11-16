#!/usr/bin/env python3
"""Build the pinned JULI formatter/guard offline; output is never installed."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


JULI_SHA256 = "83df7c64837fd51075f381b1ffbb5ecc442f8d6bc9b7db39faf2e5f6fb058c0c"
PACKAGE = "com.mellivora.bamboo.logging"
FORMATTER = PACKAGE + ".QuerySafeOneLineFormatter"
GUARD = PACKAGE + ".QuerySafeLoggingGuard"
PROBE = PACKAGE + ".startupGuard"
PRODUCTION = (
    "SecurityTokenQueryRedactor.java",
    "QuerySafeOneLineFormatter.java",
    "QuerySafeLoggingGuard.java",
)
TESTS = ("SecurityTokenQueryRedactorTest.java", "QuerySafeOneLineFormatterTest.java")
HANDLERS = (
    "1catalina.org.apache.juli.AsyncFileHandler",
    "2localhost.org.apache.juli.AsyncFileHandler",
    "3manager.org.apache.juli.AsyncFileHandler",
    "4host-manager.org.apache.juli.AsyncFileHandler",
    "5svnkit.org.apache.juli.AsyncFileHandler",
    "java.util.logging.ConsoleHandler",
)
JAR_DATE = "1980-01-01T00:00:02Z"


class BuildError(Exception):
    pass


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_new(path, text):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)

def java_environment():
    excluded = {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
                "CLASSPATH", "JAVA_OPTS", "JDK_JAVAC_OPTIONS"}
    return {key: value for key, value in os.environ.items() if key.upper() not in excluded}



def resolve_tool(name, java_home):
    if java_home is not None:
        path = java_home / "bin" / (name + (".exe" if os.name == "nt" else ""))
        native = str(path.resolve()) if path.is_file() else None
    else:
        found = shutil.which(name)
        native = str(Path(found).resolve()) if found else None
    if native:
        return [native]
    modules = {"javac": "jdk.compiler/com.sun.tools.javac.Main",
               "jar": "jdk.jartool/sun.tools.jar.Main"}
    if name not in modules:
        raise BuildError("Required Java launcher is unavailable")
    java = resolve_tool("java", java_home)
    module = modules[name]
    check = subprocess.run(java + ["--describe-module", module.split("/", 1)[0]],
                           env=java_environment(), capture_output=True, timeout=15)
    if check.returncode != 0:
        raise BuildError("Required JDK module is unavailable: " + module.split("/", 1)[0])
    # These are the real JDK compiler/archive tools, not substitute implementations.
    return java + ["--module", module]

def require_java21(java):
    result = subprocess.run(java + ["--version"], env=java_environment(),
                            capture_output=True, text=True, timeout=15)
    lines = result.stdout.splitlines()
    fields = lines[0].split() if lines else []
    if (result.returncode != 0 or len(fields) < 2
            or fields[1].split(".", 1)[0].split("-", 1)[0] != "21"):
        raise BuildError("This fixed profile requires the actual Java21 platform")
    return result.stdout.strip()



def run(command, environment, outcomes):
    # JSON argv is unambiguous on Windows and POSIX; no shell is involved.
    print("COMMAND " + json.dumps(command), flush=True)
    result = subprocess.run(command, env=environment, check=False)
    print("OUTCOME exit=" + str(result.returncode), flush=True)
    outcomes.append({"argv": command, "exit_code": result.returncode})
    if result.returncode != 0:
        raise BuildError("Command failed with exit code " + str(result.returncode))


def build(args):
    source_dir = Path(__file__).resolve().parent
    dependency = args.tomcat_juli.resolve(strict=True)
    if not dependency.is_file():
        raise BuildError("--tomcat-juli must name a regular file")
    dependency_hash = digest(dependency)
    if dependency_hash != JULI_SHA256:
        raise BuildError("tomcat-juli.jar SHA-256 does not match the fixed Tomcat 10.1.59 profile")

    source_names = PRODUCTION + TESTS + ("build.py",)
    sources = {name: source_dir / name for name in source_names}
    for path in sources.values():
        if not path.is_file():
            raise BuildError("Required source is missing: " + str(path))
    source_hashes = {name: digest(path) for name, path in sources.items()}
    java_home = args.java_home.resolve(strict=True) if args.java_home else None
    tools = {name: resolve_tool(name, java_home) for name in ("javac", "java", "jar")}
    toolchain_version = require_java21(tools["java"])

    output = args.output.absolute()
    # No parents=True or exist_ok: the caller must supply an existing parent and
    # a new final directory. Failed builds remain intact for diagnosis.
    output.mkdir()
    output = output.resolve(strict=True)
    proof = output / "proof-not-installable"
    proof.mkdir()
    classes = proof / "production-classes"
    classes.mkdir()
    test_classes = proof / "test-classes"
    test_classes.mkdir()
    write_new(proof / "NOT-INSTALLABLE.txt",
              "Compilation inputs/classes and regression tests only. Do not install this directory.\n"
              "Runtime artifact: ../querysafe-juli.jar\n")

    # Do not allow ambient JVM option/classpath variables to inject agents,
    # secrets, or alternate classes into this offline build and its test JVMs.
    environment = java_environment()
    outcomes = []
    run(tools["javac"] + ["--source", "21", "--target", "21", "-encoding", "UTF-8",
         "-classpath", str(dependency), "-d", str(classes)]
        + [str(sources[name]) for name in PRODUCTION], environment, outcomes)
    run(tools["javac"] + ["--source", "21", "--target", "21", "-encoding", "UTF-8",
         "-classpath", os.pathsep.join((str(classes), str(dependency))),
         "-d", str(test_classes)]
        + [str(sources[name]) for name in TESTS], environment, outcomes)
    test_classpath = os.pathsep.join((str(test_classes), str(classes), str(dependency)))
    for name in TESTS:
        run(tools["java"] + ["-classpath", test_classpath, PACKAGE + "." + Path(name).stem],
            environment, outcomes)

    # Guard against accidentally packaging test classes or compiler side files.
    production_files = sorted(path for path in classes.rglob("*") if path.is_file())
    if not production_files or any(path.suffix != ".class" for path in production_files):
        raise BuildError("Production compilation directory is not class-only")
    if any("Test" in path.name for path in production_files):
        raise BuildError("Test class found in production compilation directory")
    manifest_input = proof / "runtime-manifest.mf"
    write_new(manifest_input, "Manifest-Version: 1.0\nCreated-By: querysafe-juli-build\n"
              "Premain-Class: " + GUARD + "\n\n")
    runtime_jar = output / "querysafe-juli.jar"
    run(tools["jar"] + ["--create", "--file", str(runtime_jar),
         "--date=" + JAR_DATE, "--manifest", str(manifest_input)]
        + [part for path in production_files
           for part in ("-C", str(classes), path.relative_to(classes).as_posix())],
        environment, outcomes)

    if digest(dependency) != dependency_hash:
        raise BuildError("JULI dependency changed during the build")
    if any(digest(sources[name]) != source_hashes[name] for name in source_names):
        raise BuildError("Source changed during the build")
    overlay = output / "logging-formatters.properties"
    write_new(overlay,
              "# Supplemental overlay only: merge into the existing logging.properties.\n"
              "# Do not replace existing handler routes, category settings, or levels.\n"
              + "".join(handler + ".formatter = " + FORMATTER + "\n" for handler in HANDLERS)
              + PROBE + ".handlers = " + ", ".join(HANDLERS) + "\n"
              + PROBE + ".useParentHandlers = false\n")
    manifest = {
        "schema": 1,
        "profile": "tomcat-10.1.59-juli-querysafe-java21",
        "java_release": 21,
        "formatter_class": FORMATTER,
        "guard_class": GUARD,
        "premain_class": GUARD,
        "source_sha256": source_hashes,
        "tool_commands": tools,
        "java21_toolchain_version": toolchain_version,
        "compiler_policy": "Actual Java21 platform with explicit source21/target21; no cross-compilation or ct.sym substitution",
        "juli_dependency": {"filename": dependency.name, "sha256": dependency_hash},
        "runtime_jar": {"filename": runtime_jar.name, "sha256": digest(runtime_jar),
                        "size_bytes": runtime_jar.stat().st_size, "entry_date": JAR_DATE},
        "supplemental_overlay": {"filename": overlay.name, "sha256": digest(overlay)},
        "startup_probe_logger": PROBE,
        "handlers": list(HANDLERS),
        "proof_directory": proof.name,
        "proof_directory_installable": False,
        "commands": outcomes,
        "runtime_limitation": "Handlers added or reconfigured after premain require separate runtime review.",
    }
    write_new(output / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("BUILT " + str(runtime_jar), flush=True)
    print("SHA256 " + manifest["runtime_jar"]["sha256"], flush=True)
    print("REGRESSIONS 2 passed; proof directory is not installable", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tomcat-juli", type=Path, required=True,
                        help="Public tomcat-juli.jar matching the fixed SHA-256 profile")
    parser.add_argument("--output", type=Path, required=True,
                        help="New output directory under an existing parent; never overwritten")
    parser.add_argument("--java-home", type=Path,
                        help="JDK home; otherwise resolve javac, java and jar from PATH")
    args = parser.parse_args()
    try:
        build(args)
    except (BuildError, OSError) as error:
        print("BUILD FAILED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
