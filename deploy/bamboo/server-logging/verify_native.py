#!/usr/bin/env python3
"""Verify the candidate with actual audited Tomcat jars; never contact or change a service."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

from build import BuildError, java_environment, require_java21, resolve_tool

RUNTIME_SHA256 = "7783656d1456f3fa5c4ad5d67003fcc2a8d35aaa2bc910f80a7208fbdcd4683d"
JARS = {"annotations-api.jar", "catalina.jar", "jaspic-api.jar", "servlet-api.jar",
        "tomcat-api.jar", "tomcat-coyote.jar", "tomcat-util-scan.jar", "tomcat-util.jar", "tomcat-juli.jar"}
FORMATTER = "com.mellivora.bamboo.logging.QuerySafeOneLineFormatter"
PROBE = "com.mellivora.bamboo.logging.startupGuard"
MAIN = "com.mellivora.bamboo.logging.NativeJulLoggingSmoke"
HANDLERS = [name + ".org.apache.juli.AsyncFileHandler" for name in
            ("1catalina", "2localhost", "3manager", "4host-manager", "5svnkit")]
HANDLERS += ["6direct.org.apache.juli.FileHandler", "java.util.logging.ConsoleHandler"]
CASES = ("protected", "protected-root-subset", "protected-localized", "native-formatter",
         "missing-formatter-class", "missing-probe", "wrong-juli-digest")
PRIVATE_MARKERS = ("CD08_PRIVATE_NATIVE_RAW_20261113", "CD08_PRIVATE_NATIVE_ERROR_20261113",
                   "CD08_PRIVATE_NATIVE_CAUSE_20261113", "CD08_PRIVATE_NATIVE_ENCODED_20261113")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def properties(root):
    handlers = ", ".join(HANDLERS)
    rows = ["handlers = " + handlers, ".handlers = " + handlers, ".level = ALL",
            PROBE + ".handlers = " + handlers, PROBE + ".useParentHandlers = false"]
    for index, handler in enumerate(HANDLERS):
        rows += [handler + ".formatter = " + FORMATTER, handler + ".level = ALL",
                 handler + ".encoding = UTF-8"]
        if handler != "java.util.logging.ConsoleHandler":
            # Forward slashes are valid on both platforms and avoid Properties backslash escapes.
            rows += [handler + ".directory = " + (root / "logs").as_posix(),
                     handler + ".prefix = sink" + str(index) + ".",
                     handler + ".suffix = log", handler + ".rotatable = false"]
    return "\n".join(rows) + "\n"


def rewritten_jar(source, destination, excluded=None, manifest_extra=None):
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(destination, "w") as new:
        for item in old.infolist():
            if item.filename == excluded:
                continue
            data = old.read(item.filename)
            if item.filename.upper() == "META-INF/MANIFEST.MF" and manifest_extra:
                data = data.rstrip(b"\r\n") + b"\r\n" + manifest_extra + b"\r\n\r\n"
            new.writestr(item, data)


def verify(args):
    package = args.package.resolve(strict=True)
    runtime = args.runtime_archive.resolve(strict=True)
    require(digest(runtime) == RUNTIME_SHA256, "Runtime archive differs from the audited public snapshot")
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    jar = package / "querysafe-juli.jar"
    require(digest(jar) == manifest["runtime_jar"]["sha256"], "Candidate JAR digest mismatch")
    root = args.output.absolute()
    root.mkdir()  # Exclusive; preserve failed proof files instead of deleting caller data.
    root = root.resolve()
    lib = root / "lib"
    lib.mkdir()
    with tarfile.open(runtime, "r:gz") as archive:
        members = archive.getmembers()
        require({member.name for member in members} == JARS and len(members) == len(JARS),
                "Unexpected runtime archive members")
        for member in members:
            require(member.isfile() and Path(member.name).name == member.name
                    and "/" not in member.name and "\\" not in member.name, "Unsafe runtime member")
            with archive.extractfile(member) as stream:
                (lib / member.name).write_bytes(stream.read())
    source = Path(__file__).resolve().with_name("NativeJulLoggingSmoke.java")
    classes = root / "test-classes"
    classes.mkdir()
    environment = java_environment()
    tools = {name: resolve_tool(name, args.java_home) for name in ("java", "javac")}
    toolchain_version = require_java21(tools["java"])
    native_jars = [lib / name for name in sorted(JARS)]
    compile_cp = os.pathsep.join(str(p) for p in [jar] + native_jars)
    compile_result = subprocess.run(tools["javac"] + ["--source", "21", "--target", "21", "-encoding", "UTF-8",
                                     "-cp", compile_cp, "-d", str(classes), str(source)],
                                    env=environment, capture_output=True, text=True, timeout=60)
    require(compile_result.returncode == 0, "Native fixture compilation failed: " + compile_result.stderr)
    results = {}
    for case in args.case or CASES:
        directory = root / case
        directory.mkdir()
        (directory / "logs").mkdir()
        text = properties(directory)
        candidate = jar
        case_jars = native_jars
        if case in ("protected-root-subset", "protected-localized"):
            # Real Bamboo root routes only catalina/console; exercise independently named sinks too.
            all_handlers = ", ".join(HANDLERS)
            text = text.replace("\n.handlers = " + all_handlers,
                                "\n.handlers = " + ", ".join((HANDLERS[0], HANDLERS[-1])), 1)
            for name in ("org.apache.catalina.valves.StuckThreadDetectionValve", "querysafe.native.diagnostics"):
                text += name + ".handlers = " + all_handlers + "\n" + name + ".useParentHandlers = false\n"
        if case == "native-formatter":
            text = text.replace(HANDLERS[0] + ".formatter = " + FORMATTER,
                                HANDLERS[0] + ".formatter = org.apache.juli.OneLineFormatter")
        elif case == "missing-formatter-class":
            candidate = directory / "guard-missing-formatter.jar"
            rewritten_jar(jar, candidate, excluded="com/mellivora/bamboo/logging/QuerySafeOneLineFormatter.class")
        elif case == "missing-probe":
            text = "\n".join(line for line in text.splitlines() if not line.startswith(PROBE + ".handlers")) + "\n"
        elif case == "wrong-juli-digest":
            changed = directory / "modified-tomcat-juli.jar"
            rewritten_jar(lib / "tomcat-juli.jar", changed, manifest_extra=b"Fixture-Modification: true")
            case_jars = [changed if p.name == "tomcat-juli.jar" else p for p in native_jars]
        config = directory / "logging.properties"
        with config.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(text)
        # Candidate deliberately absent from -cp: -javaagent must make formatter visible to system loader.
        classpath = os.pathsep.join(str(p) for p in [classes] + case_jars)
        locale_options = ["-Duser.language=zh", "-Duser.country=CN"] if case == "protected-localized" else []
        command = tools["java"] + locale_options + ["-XX:-CreateCoredumpOnCrash",
                   "-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager",
                   "-Djava.util.logging.config.file=" + str(config), "-javaagent:" + str(candidate),
                   "-cp", classpath, MAIN, str(directory)]
        process = subprocess.run(command, env=environment, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=60, cwd=directory)
        entered = (directory / "application-started").exists()
        if case in ("protected", "protected-root-subset", "protected-localized"):
            require(process.returncode == 0 and entered, "Protected native fixture failed: " + process.stderr)
            require(not any(marker in process.stderr for marker in PRIVATE_MARKERS),
                    "Synthetic credential survived console formatter")
            require(all(marker in process.stderr for marker in ("QUERYSAFE_ERROR", "QUERYSAFE_PARAMETERS",
                    "QUERYSAFE_UNICODE", "GetFingerprint.action?securityToken=[REDACTED]",
                    "Caused by:", "Suppressed:", "UsefulCauseFrame", "UsefulSuppressedFrame")),
                    "Console diagnostic context was suppressed")
            summaries = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
            require(len(summaries) == 1 and summaries[0]["native_stuck_warning_redacted"],
                    "Native warning proof missing")
            results[case] = {"exit_code": process.returncode, **summaries[0],
                             "console_pending_parent_verification": False,
                             "console_verified": True, "candidate_not_in_application_classpath": True}
        else:
            require(process.returncode != 0 and not entered, "Unsafe logging configuration entered application main")
            require("JUL_GUARD_" in process.stderr, "Expected startup policy rejection missing")
            results[case] = {"exit_code": process.returncode, "application_main_entered": False,
                             "startup_rejected": True}
        print(case + ": " + json.dumps(results[case], sort_keys=True), flush=True)
    report = {"schema": 1, "runtime_archive_sha256": RUNTIME_SHA256,
              "candidate_jar_sha256": digest(jar), "juli_dependency_sha256": digest(lib / "tomcat-juli.jar"),
              "fixture_source_sha256": digest(source), "runner_source_sha256": digest(Path(__file__)),
              "java21_toolchain_version": toolchain_version,
              "results": results, "production_http_requests": 0,
              "runtime_reconfiguration_after_premain_not_covered": True}
    (root / "native-proof.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("NATIVE PROOF " + str(root / "native-proof.json"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--java-home", type=Path)
    parser.add_argument("--case", action="append", choices=CASES,
                        help="Run only a newly added/changed native scenario; default runs every case")
    args = parser.parse_args()
    try:
        verify(args)
    except (BuildError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as failure:
        print("NATIVE PROOF FAILED: " + str(failure), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
