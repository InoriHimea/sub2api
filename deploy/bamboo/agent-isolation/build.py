#!/usr/bin/env python3
"""Offline Bamboo 12.1.12 isolation candidate compiler; never installs or runs proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

PACKAGE = "com.mellivora.bamboo.isolation"
REMOTE = "com/atlassian/bamboo/v2/build/agent/remote/"
PINNED = {
    "atlassian-bamboo-agent-bootstrap-12.1.12.jar": "030c7ebb4ef5182fc063c7e46235f6da07aaed0630183a2d0f3e79a78205ea6b",
    "atlassian-bamboo-agent-remote-12.1.12.jar": "79c14a4800146f563293452644600a693f650745f58d425a53aaf782427d722e",
    "atlassian-bamboo-agent-core-12.1.12.jar": "891c5158ad15ab78917af21ffb867311ec984bc2b06ee0eeeb96f87015e4f595",
    "atlassian-bamboo-api-12.1.12.jar": "daa4f10c404a05d23e2b7ad3dd09c57aa3e0a605208006cc8eded75bd9456b23",
    "atlassian-bamboo-core-12.1.12.jar": "e5682254bed1198b13ca6a4faff95e305915f8de13b59761ad254c2378869c3c",
}
NATIVE = {
    REMOTE + "RemoteAgent.class": "d6e98472d174b865217bf66db5cc76d915d1d0922200414e78d91f38d64f3980",
    REMOTE + "AgentRegistrationBean.class": "6f3d3905cd1c3557e39190c9626cc7fadbd370499364ad0fd0634e6f3b753b1c",
    REMOTE + "AgentConfiguration.class": "adbd1424f261945b4498b723e59651c49b282522c3ea4b349926eef388a41e08",
    "com/atlassian/bamboo/agent/bootstrap/classloading/ConditionallyDelegatingUrlClassLoader.class": "c13136c47e1e9797311f371b428bff5ab94f8456432400e655a210bda20ff0e9",
}
XMLS = {
    "applicationContextRemoteAgentStartupCore.xml": ("f022a50d6a6e7cbf9929c5850cc8ef8a1ca3b3c306a3b0c85b60c7ddadb20b96", ("agentMessageListenerConnector", "remoteEventRebroadcasterMessageListenerContainer", "executableBuildAgent", "heartBeatScheduler"), {"agentMessageListenerConnector", "remoteEventRebroadcasterMessageListenerContainer", "executableBuildAgent", "heartBeatScheduler", "remoteAgentPluginManager", "deferredPluginEventHandler"}),
    "applicationContextRemoteLongLivedAgentStartupCore.xml": ("7da5c09eddb16b975094d2d41ccdfc63c75c401b6a77184a6e8b501e4cbd25d0", ("remoteEventRebroadcasterMessageListenerContainerLongLived",), {"remoteEventRebroadcasterMessageListenerContainerLongLived"}),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def environment():
    excluded = {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "JAVA_OPTS", "JDK_JAVAC_OPTIONS"}
    return {k: v for k, v in os.environ.items() if k.upper() not in excluded}


def tool(name, home):
    native = home / "bin" / (name + (".exe" if os.name == "nt" else "")) if home else None
    found = str(native.resolve()) if native and native.is_file() else (shutil.which(name) if not home else None)
    if found:
        return [found]
    if name != "javac":
        raise ValueError("Java launcher unavailable")
    java = tool("java", home)
    subprocess.run(java + ["--describe-module", "jdk.compiler"], env=environment(), check=True, capture_output=True)
    return java + ["--module", "jdk.compiler/com.sun.tools.javac.Main"]


def jar(path, entries):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(entries.items()):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 2))
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            archive.writestr(item, data)


def overlay(data, filename, uid):
    expected_hash, targets, expected_names = XMLS[filename]
    if sha(data) != expected_hash:
        raise ValueError("Pinned native XML mismatch")
    text = data.decode("utf-8")
    root = ET.fromstring(text)
    names = {b.get("id") or b.get("name") for b in root.findall("{http://www.springframework.org/schema/beans}bean") if b.get("id") or b.get("name")}
    if names != expected_names:
        raise ValueError("Native bean set mismatch")
    for name in targets:
        pattern = re.compile(r'(<bean\s+id="' + re.escape(name) + r'"[^>]*)(>)')
        matches = list(pattern.finditer(text))
        if len(matches) != 1:
            raise ValueError("Native dependency target mismatch")
        def amend(match):
            opening = match.group(1)
            dependency = re.search(r'depends-on="([^"]*)"', opening)
            if dependency:
                opening = opening[:dependency.start(1)] + dependency.group(1) + " isolationActivationGate" + opening[dependency.end(1):]
            else:
                opening += ' depends-on="isolationActivationGate"'
            return opening + match.group(2)
        text = pattern.sub(amend, text)
    # One gate definition only, shared by both stock contexts.
    if filename == "applicationContextRemoteAgentStartupCore.xml":
        gate = '''  <bean id="isolationActivationGate" class="com.mellivora.bamboo.isolation.ActivationGate" depends-on="agentRegistrationBean" init-method="initialize">
    <constructor-arg value="#{systemProperties['bamboo.isolation.profile']}"/>
    <constructor-arg value="#{agentConfiguration.getAgentId()}"/>
    <constructor-arg value="#{remoteAgent.getUuid().toString()}"/>
    <constructor-arg value="#{remoteAgent.getAgentContext().getBaseUrl().toExternalForm()}"/>
    <constructor-arg value="UID"/>
  </bean>
'''.replace("UID", str(uid))
        text = text.replace("</beans>", gate + "</beans>")
    return text.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--java-home", type=Path)
    args = parser.parse_args()
    native = args.native_dir.resolve()
    # External dependency hashes are provenance inputs, never trusted to change the pinned vendor target bytes.
    provenance = json.loads((native / "inputs.json").read_text(encoding="utf-8"))
    jars = sorted(native.glob("*.jar"))
    if not jars:
        raise ValueError("No native inputs")
    for path in jars:
        actual = sha(path.read_bytes())
        if path.name not in provenance or actual != provenance[path.name]["sha256"]:
            raise ValueError("Dependency provenance mismatch: " + path.name)
    for name, expected in PINNED.items():
        if sha((native / name).read_bytes()) != expected:
            raise ValueError("Pinned native artifact mismatch: " + name)
    entries = {}
    for path in jars:
        with zipfile.ZipFile(path) as archive:
            for name in set(NATIVE) | set(XMLS):
                if name in archive.namelist():
                    if name in entries:
                        raise ValueError("Duplicate native target")
                    entries[name] = archive.read(name)
    for name, expected in NATIVE.items():
        if sha(entries[name]) != expected:
            raise ValueError("Pinned native class mismatch")
    java, javac = tool("java", args.java_home), tool("javac", args.java_home)
    version = subprocess.run(java + ["--version"], env=environment(), check=True, capture_output=True, text=True).stdout
    if not re.match(r"\S+ 21(?:[.\s+-])", version):
        raise ValueError("Actual JDK21 required")
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    production = out / "candidate-classes"
    proof = out / "proof-not-installable"
    production.mkdir()
    proof.mkdir()
    source = Path(__file__).resolve().parent
    sources = [source / (name + ".java") for name in ("ActivationGate", "GuardedBootstrap", "IsolationRuntimeGuard")]
    subprocess.run(javac + ["-proc:none", "-source", "21", "-target", "21", "-encoding", "UTF-8", "-d", str(production)] + [str(p) for p in sources], env=environment(), check=True)
    packed = {str(p.relative_to(production)).replace(os.sep, "/"): p.read_bytes() for p in production.rglob("*.class")}
    packed["META-INF/MANIFEST.MF"] = ("Manifest-Version: 1.0\r\nPremain-Class: " + PACKAGE + ".IsolationRuntimeGuard\r\n\r\n").encode("ascii")
    for name in XMLS:
        packed[name] = overlay(entries[name], name, 0)
    packed["isolation-resource-sha256.properties"] = "".join(name + "=" + sha(packed[name]) + "\n" for name in sorted(XMLS)).encode("ascii")
    packed["isolation-native-sha256.properties"] = "".join(name + "=" + expected + "\n" for name, expected in sorted(NATIVE.items())).encode("ascii")
    candidate = out / "bamboo-isolation-candidate.jar"
    jar(candidate, packed)
    # Proof variants cannot be installed: names and manifests intentionally separate.
    for variant in ("missing-xml", "changed-xml"):
        changed = dict(packed)
        name = next(iter(XMLS))
        if variant == "missing-xml":
            del changed[name]
        else:
            changed[name] += b"\n<!-- proof mutation -->\n"
        jar(proof / (variant + ".jar"), changed)
    name = REMOTE + "AgentRegistrationBean.class"
    wrong = bytearray(entries[name])
    wrong[-1] ^= 1
    jar(proof / "wrong-native.jar", {name: bytes(wrong)})
    for name in XMLS:
        (proof / "graph").mkdir(exist_ok=True)
        # Inspectable consumer proof uses the same gate, but catches its denial instead of
        # halting the observer JVM. Separate subprocesses qualify the production exit path.
        graph = overlay(entries[name], name, 1000).replace(b'init-method="initialize"', b'init-method="awaitActivation"')
        (proof / "graph" / name).write_bytes(graph)
    cp = os.pathsep.join([str(candidate)] + [str(p) for p in jars])
    subprocess.run(javac + ["-proc:none", "-source", "21", "-target", "21", "-encoding", "UTF-8", "-cp", cp, "-d", str(proof), str(source / "NativeIsolationSmoke.java"), str(source / "NativeAssignmentSmoke.java"), str(source / "NativeLoaderSmoke.java")], env=environment(), check=True)
    report = {"java": version.strip(), "candidate_sha256": sha(candidate.read_bytes()), "native": NATIVE, "inputs": {p.name: sha(p.read_bytes()) for p in jars}, "sources": {p.name: sha(p.read_bytes()) for p in sources + [source / "NativeIsolationSmoke.java", source / "NativeAssignmentSmoke.java", source / "NativeLoaderSmoke.java", Path(__file__).resolve()]}, "proof_executed": False, "scope": "Offline candidate only; no real bootstrap, server registration algorithm or full RemoteAgent context"}
    (out / "build-evidence.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    command = java + ["-javaagent:" + str(candidate), "-cp", os.pathsep.join([str(proof), cp]), PACKAGE + ".NativeIsolationSmoke", str(out), str(native)]
    print("PROOF_COMMAND " + json.dumps(command))
    assignment = java + ["-cp", os.pathsep.join([str(proof), cp]), PACKAGE + ".proof.NativeAssignmentSmoke"]
    print("ASSIGNMENT_COMMAND " + json.dumps(assignment))
    loader = java + ["-javaagent:" + str(candidate), "-cp", os.pathsep.join([str(proof), cp]), PACKAGE + ".proof.NativeLoaderSmoke", str(candidate), str(native)]
    print("LOADER_COMMAND " + json.dumps(loader))


if __name__ == "__main__":
    main()
