package com.mellivora.bamboo.isolation;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Observes (never rewrites) hash-pinned native class definitions before they can execute. */
public final class IsolationRuntimeGuard {
    private static volatile boolean armed;

    private IsolationRuntimeGuard() {
    }

    public static boolean isArmed() {
        return armed;
    }

    public static synchronized void premain(String arguments, Instrumentation instrumentation) {
        try {
            if (armed || instrumentation == null || (arguments != null && !arguments.isEmpty())) {
                stop();
                return;
            }
            Map<String, String> hashes = new HashMap<>();
            Set<String> targetNames = new HashSet<>();
            for (var entry : GuardedBootstrap.nativeHashes().entrySet()) {
                String internalName = entry.getKey().substring(0, entry.getKey().length() - 6);
                hashes.put(internalName, entry.getValue());
                targetNames.add(internalName.replace('/', '.'));
            }
            // Checking already loaded targets is deliberately fail-closed: their defining bytes
            // cannot be established by subsequently reading an on-disk class resource.
            rejectLoadedTargets(instrumentation, targetNames);
            instrumentation.addTransformer(new ClassFileTransformer() {
                @Override
                public byte[] transform(ClassLoader loader, String className, Class<?> redefined,
                                        ProtectionDomain domain, byte[] bytes) {
                    try {
                        String expected = className == null ? null : hashes.get(className);
                        if (expected != null && (bytes == null
                                || !expected.equals(GuardedBootstrap.sha256(bytes)))) {
                            stop();
                        }
                    } catch (Throwable failure) {
                        // Instrumentation swallows transformer exceptions. Only halt is fail-stop.
                        stop();
                    }
                    return null;
                }
            }, false);
            // A target that raced the installation cannot be retrospectively trusted, even if
            // the transformer also saw it. The bootstrap has not been allowed to run yet.
            rejectLoadedTargets(instrumentation, targetNames);
            armed = true;
        } catch (Throwable failure) {
            stop();
        }
    }

    private static void rejectLoadedTargets(Instrumentation instrumentation, Set<String> targetNames) {
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            if (targetNames.contains(loaded.getName())) {
                stop();
            }
        }
    }

    private static void stop() {
        try {
            System.err.println("ISOLATION_NATIVE_DENIED");
        } finally {
            Runtime.getRuntime().halt(78);
        }
    }
}
