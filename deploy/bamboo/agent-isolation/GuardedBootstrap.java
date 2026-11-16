package com.mellivora.bamboo.isolation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Validates the overlay in its own packaged JAR before entering the unchanged bootstrap. */
public final class GuardedBootstrap {
    private static final int MAX_MANIFEST_BYTES = 16384;
    private static final int MAX_XML_BYTES = 1048576;
    static final String RESOURCE_MANIFEST = "isolation-resource-sha256.properties";
    static final String NATIVE_MANIFEST = "isolation-native-sha256.properties";
    static final Set<String> XML_RESOURCES = Set.of("applicationContextRemoteAgentStartupCore.xml",
            "applicationContextRemoteLongLivedAgentStartupCore.xml");
    static final Set<String> NATIVE_RESOURCES = Set.of(
            "com/atlassian/bamboo/v2/build/agent/remote/RemoteAgent.class",
            "com/atlassian/bamboo/v2/build/agent/remote/AgentRegistrationBean.class",
            "com/atlassian/bamboo/v2/build/agent/remote/AgentConfiguration.class",
            "com/atlassian/bamboo/agent/bootstrap/classloading/ConditionallyDelegatingUrlClassLoader.class");

    private GuardedBootstrap() {
    }

    public static void main(String[] args) {
        try {
            if (!IsolationRuntimeGuard.isArmed()) {
                throw denied();
            }
            verifyResources();
            Class<?> delegate = Class.forName("com.mellivora.bamboo.SecureBambooBootstrap", true,
                    GuardedBootstrap.class.getClassLoader());
            delegate.getMethod("main", String[].class).invoke(null, (Object) args);
        } catch (Throwable failure) {
            // Neither arguments nor reflective/delegate exception text may escape this boundary.
            try {
                System.err.println("ISOLATION_BOOTSTRAP_DENIED");
            } finally {
                Runtime.getRuntime().halt(78);
            }
        }
    }

    /** Qualification entry point: checks packaging only, never invokes the real bootstrap. */
    public static void verifyResources() {
        try {
            Path own = ownJar();
            Map<String, String> xml = readManifest(own, RESOURCE_MANIFEST, XML_RESOURCES);
            readManifest(own, NATIVE_MANIFEST, NATIVE_RESOURCES);
            for (String resource : XML_RESOURCES) {
                verifyOrigin(own, resource);
                if (!xml.get(resource).equals(sha256(readEntry(own, resource, MAX_XML_BYTES)))) {
                    throw denied();
                }
            }
        } catch (Exception failure) {
            throw denied();
        }
    }

    static Map<String, String> nativeHashes() {
        try {
            return readManifest(ownJar(), NATIVE_MANIFEST, NATIVE_RESOURCES);
        } catch (Exception failure) {
            throw denied();
        }
    }

    private static Map<String, String> readManifest(Path own, String name, Set<String> expected)
            throws Exception {
        verifyOrigin(own, name);
        Properties properties = new Properties() {
            @Override
            public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) {
                    throw denied();
                }
                return super.put(key, value);
            }
        };
        properties.load(new ByteArrayInputStream(readEntry(own, name, MAX_MANIFEST_BYTES)));
        if (!properties.stringPropertyNames().equals(expected)) {
            throw denied();
        }
        java.util.HashMap<String, String> result = new java.util.HashMap<>();
        for (String key : expected) {
            String digest = properties.getProperty(key);
            if (!digest.matches("[0-9a-f]{64}")) {
                throw denied();
            }
            result.put(key, digest);
        }
        return Map.copyOf(result);
    }

    private static Path ownJar() throws Exception {
        URL location = GuardedBootstrap.class.getProtectionDomain().getCodeSource().getLocation();
        if (!"file".equals(location.getProtocol())) {
            throw denied();
        }
        Path jar = Path.of(location.toURI()).toRealPath();
        if (!Files.isRegularFile(jar)) {
            throw denied();
        }
        for (Class<?> type : new Class<?>[] {IsolationRuntimeGuard.class, ActivationGate.class}) {
            URL origin = type.getProtectionDomain().getCodeSource().getLocation();
            if (!"file".equals(origin.getProtocol())
                    || !jar.equals(Path.of(origin.toURI()).toRealPath())) {
                throw denied();
            }
        }
        return jar;
    }

    private static void verifyOrigin(Path own, String resource) throws Exception {
        ClassLoader loader = GuardedBootstrap.class.getClassLoader();
        URL resolved = loader.getResource(resource);
        if (resolved == null || !(resolved.openConnection() instanceof JarURLConnection connection)) {
            throw denied();
        }
        connection.setUseCaches(false);
        if (!resource.equals(connection.getEntryName())
                || !"file".equals(connection.getJarFileURL().getProtocol())
                || !own.equals(Path.of(connection.getJarFileURL().toURI()).toRealPath())) {
            throw denied();
        }
    }

    private static byte[] readEntry(Path own, String name, int maximum) throws IOException {
        try (JarFile jar = new JarFile(own.toFile(), true)) {
            JarEntry entry = jar.getJarEntry(name);
            if (entry == null || entry.isDirectory() || entry.getSize() < 0 || entry.getSize() > maximum) {
                throw denied();
            }
            try (InputStream input = jar.getInputStream(entry)) {
                byte[] bytes = input.readNBytes(maximum + 1);
                if (bytes.length > maximum || bytes.length != entry.getSize()) {
                    throw denied();
                }
                return bytes;
            }
        }
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception failure) {
            throw denied();
        }
    }

    private static IllegalStateException denied() {
        return new IllegalStateException("ISOLATION_RESOURCES_DENIED");
    }
}
