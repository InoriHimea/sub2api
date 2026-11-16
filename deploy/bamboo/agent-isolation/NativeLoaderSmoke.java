package com.mellivora.bamboo.isolation.proof;

import com.atlassian.bamboo.agent.bootstrap.classloading.ConditionallyDelegatingUrlClassLoader;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.core.io.ClassPathResource;

/** Exercises the genuine native child loader without invoking any bootstrap or agent entry point. */
public final class NativeLoaderSmoke {
    public static void main(String[] args) throws Exception {
        Path candidate = Path.of(args[0]).toRealPath();
        Path nativeDirectory = Path.of(args[1]).toRealPath();
        List<Path> libraries;
        try (var paths = Files.list(nativeDirectory)) {
            libraries = paths.filter(p -> p.getFileName().toString().endsWith(".jar")).sorted().toList();
        }
        URL[] nativeUrls = new URL[libraries.size()];
        for (int i = 0; i < nativeUrls.length; i++) nativeUrls[i] = libraries.get(i).toUri().toURL();
        // The parent contains only the JDK-only candidate, never a shadow RemoteAgent implementation.
        try (URLClassLoader parent = new URLClassLoader(new URL[]{candidate.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader());
             ConditionallyDelegatingUrlClassLoader child = new ConditionallyDelegatingUrlClassLoader(nativeUrls, parent)) {
            ClassLoader prior = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(child);
                for (String resource : List.of("applicationContextRemoteAgentStartupCore.xml",
                        "applicationContextRemoteLongLivedAgentStartupCore.xml")) {
                    URL resolved = new ClassPathResource(resource).getURL();
                    if (!(resolved.openConnection() instanceof JarURLConnection entry)
                            || !candidate.equals(Path.of(entry.getJarFileURL().toURI()).toRealPath())) {
                        throw new AssertionError("Native child did not select parent overlay");
                    }
                }
                Class<?> gate = child.loadClass("com.mellivora.bamboo.isolation.GuardedBootstrap");
                if (gate.getClassLoader() != parent) throw new AssertionError("Gate was not parent-defined");
                gate.getMethod("verifyResources").invoke(null);
                Class<?> remote = child.loadClass("com.atlassian.bamboo.v2.build.agent.remote.RemoteAgent");
                if (remote.getClassLoader() != child || !nativeDirectory.resolve(
                        "atlassian-bamboo-agent-remote-12.1.12.jar").toRealPath().equals(
                        Path.of(remote.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath())) {
                    throw new AssertionError("RemoteAgent was replaced or came from an unexpected artifact");
                }
            } finally {
                Thread.currentThread().setContextClassLoader(prior);
            }
        }
        System.out.println("PASS native-parent-first-overlays-and-real-vendor-RemoteAgent-origin");
    }
}
