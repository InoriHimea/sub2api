package com.mellivora.bamboo.isolation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** A one-shot, post-registration operator-attestation barrier, not a server-state query. */
public final class ActivationGate {
    private static final int MAX_BYTES = 16384;
    private static final Set<String> PROFILE_KEYS = Set.of("schema", "agent.id", "agent.uuid",
            "server.url", "assignments.sha256", "wait.millis", "request.directory", "permit.path");
    private static final Set<String> PERMIT_KEYS = Set.of("schema", "nonce", "agent.id", "agent.uuid",
            "server.url", "assignments.sha256", "server.enabled", "server.exclusive",
            "issued.at.millis", "expires.at.millis");
    private static final Set<String> DISCOVERY_KEYS = Set.of("schema", "mode", "server.url", "receipt.directory");
    // Spring can retry a failed bean with a new instance. Discovery must survive that retry.
    private static final AtomicBoolean DISCOVERY_ENTERED = new AtomicBoolean();
    private static final AtomicReference<String> PROCESS_MODE = new AtomicReference<>();
    private final String profilePath;
    private final long registeredId;
    private final String registeredUuid;
    private final String serverUrl;
    private final long trustedUid;
    private final long startupMillis = System.currentTimeMillis();
    private boolean invoked;

    public ActivationGate(String profilePath, long registeredId, String registeredUuid,
                          String serverUrl, long trustedUid) {
        this.profilePath = profilePath;
        this.registeredId = registeredId;
        this.registeredUuid = registeredUuid;
        this.serverUrl = serverUrl;
        this.trustedUid = trustedUid;
    }

    /** Spring production entry: discovery must end the JVM, not just its runner thread. */
    public void initialize() {
        try {
            awaitActivation();
        } catch (RuntimeException denied) {
            if ("registration-only".equals(PROCESS_MODE.get())) {
                Runtime.getRuntime().halt(78);
            }
            throw denied;
        }
    }

    public synchronized void awaitActivation() {
        if (invoked) {
            throw denied("ISOLATION_GATE_REUSED");
        }
        invoked = true;
        try {
            if (DISCOVERY_ENTERED.get()) {
                throw denied("ISOLATION_DISCOVERY_LOCKED");
            }
            Properties profile = parse(readTrusted(absolute(profilePath), trustedUid), null);
            String mode = "registration-only".equals(profile.getProperty("mode"))
                    ? "registration-only" : "activation";
            PROCESS_MODE.compareAndSet(null, mode);
            if (!mode.equals(PROCESS_MODE.get())) {
                throw denied("ISOLATION_MODE_LOCKED");
            }
            if (trustedUid < 0 || registeredId <= 0 || serverUrl == null || serverUrl.isEmpty()) {
                throw denied("ISOLATION_IDENTITY");
            }
            canonicalUuid(registeredUuid);
            if ("registration-only".equals(profile.getProperty("mode"))) {
                if (!DISCOVERY_ENTERED.compareAndSet(false, true)) {
                    throw denied("ISOLATION_DISCOVERY_LOCKED");
                }
                if (!profile.stringPropertyNames().equals(DISCOVERY_KEYS)
                        || !"1".equals(profile.getProperty("schema"))
                        || !serverUrl.equals(profile.getProperty("server.url"))) {
                    throw denied("ISOLATION_DISCOVERY_PROFILE");
                }
                Properties receipt = new Properties();
                receipt.setProperty("schema", "1");
                receipt.setProperty("mode", "registration-only");
                receipt.setProperty("nonce", UUID.randomUUID().toString());
                receipt.setProperty("agent.id", Long.toString(registeredId));
                receipt.setProperty("agent.uuid", registeredUuid);
                receipt.setProperty("server.url", serverUrl);
                ByteArrayOutputStream serialized = new ByteArrayOutputStream();
                receipt.store(serialized, null);
                if (serialized.size() > MAX_BYTES) {
                    throw denied("ISOLATION_REQUEST");
                }
                writeRequest(absolute(profile.getProperty("receipt.directory")),
                        receipt.getProperty("nonce"), serialized.toByteArray());
                // Never return to Spring: successful discovery is still a startup denial.
                throw denied("ISOLATION_DISCOVERY_COMPLETE");
            }
            if (!profile.stringPropertyNames().equals(PROFILE_KEYS)) {
                throw denied("ISOLATION_SCHEMA");
            }
            if (!"1".equals(profile.getProperty("schema"))
                    || positive(profile.getProperty("agent.id")) != registeredId
                    || !registeredUuid.equals(canonicalUuid(profile.getProperty("agent.uuid")))
                    || !serverUrl.equals(profile.getProperty("server.url"))) {
                throw denied("ISOLATION_IDENTITY");
            }
            String assignments = profile.getProperty("assignments.sha256");
            if (!assignments.matches("[0-9a-f]{64}")) {
                throw denied("ISOLATION_PROFILE");
            }
            long waitMillis = positive(profile.getProperty("wait.millis"));
            if (waitMillis > 300000) {
                throw denied("ISOLATION_PROFILE");
            }
            Path requestDirectory = absolute(profile.getProperty("request.directory"));
            Path permitPath = absolute(profile.getProperty("permit.path"));
            String nonce = UUID.randomUUID().toString();
            Properties request = new Properties();
            request.setProperty("schema", "1");
            request.setProperty("nonce", nonce);
            request.setProperty("agent.id", Long.toString(registeredId));
            request.setProperty("agent.uuid", registeredUuid);
            request.setProperty("server.url", serverUrl);
            request.setProperty("assignments.sha256", assignments);
            ByteArrayOutputStream serialized = new ByteArrayOutputStream();
            request.store(serialized, null);
            if (serialized.size() > MAX_BYTES) {
                throw denied("ISOLATION_REQUEST");
            }
            long start = System.nanoTime();
            writeRequest(requestDirectory, nonce, serialized.toByteArray());
            long budget = TimeUnit.MILLISECONDS.toNanos(waitMillis);
            while (System.nanoTime() - start < budget) {
                try {
                    Properties permit = parse(readTrusted(permitPath, trustedUid), PERMIT_KEYS);
                    validatePermit(permit, nonce, assignments);
                    if (System.nanoTime() - start >= budget) {
                        throw denied("ISOLATION_TIMEOUT");
                    }
                    return;
                } catch (java.nio.file.NoSuchFileException missing) {
                    // Only an absent permit waits. Existing malformed/untrusted permits deny immediately.
                }
                long remaining = budget - (System.nanoTime() - start);
                if (remaining > 0) {
                    TimeUnit.NANOSECONDS.sleep(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(50)));
                }
            }
            throw denied("ISOLATION_TIMEOUT");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw denied("ISOLATION_INTERRUPTED");
        } catch (GateDenied fixed) {
            throw fixed;
        } catch (Exception failure) {
            throw denied("ISOLATION_GATE_DENIED");
        }
    }

    private void validatePermit(Properties permit, String nonce, String assignments) {
        long now = System.currentTimeMillis();
        long issued = positive(permit.getProperty("issued.at.millis"));
        long expires = positive(permit.getProperty("expires.at.millis"));
        if (!"1".equals(permit.getProperty("schema"))
                || !nonce.equals(permit.getProperty("nonce"))
                || positive(permit.getProperty("agent.id")) != registeredId
                || !registeredUuid.equals(permit.getProperty("agent.uuid"))
                || !serverUrl.equals(permit.getProperty("server.url"))
                || !assignments.equals(permit.getProperty("assignments.sha256"))
                || !"true".equals(permit.getProperty("server.enabled"))
                || !"true".equals(permit.getProperty("server.exclusive"))
                || issued < startupMillis - 5000 || issued > now + 5000
                || expires <= now || expires <= issued || expires - issued > 300000) {
            throw denied("ISOLATION_PERMIT");
        }
    }

    private static Path absolute(String value) {
        if (value == null || value.isEmpty()) {
            throw denied("ISOLATION_PATH");
        }
        Path path = Path.of(value);
        if (!path.isAbsolute() || !path.equals(path.normalize()) || path.getParent() == null) {
            throw denied("ISOLATION_PATH");
        }
        return path;
    }

    private static String canonicalUuid(String value) {
        if (value == null || !UUID.fromString(value).toString().equals(value)) {
            throw denied("ISOLATION_IDENTITY");
        }
        return value;
    }

    private static long positive(String value) {
        if (value == null || !value.matches("[1-9][0-9]{0,18}")) {
            throw denied("ISOLATION_SCHEMA");
        }
        long result = Long.parseLong(value);
        if (result <= 0) {
            throw denied("ISOLATION_SCHEMA");
        }
        return result;
    }

    private static Properties parse(byte[] bytes, Set<String> keys) throws IOException {
        Properties properties = new Properties() {
            @Override
            public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) {
                    throw denied("ISOLATION_SCHEMA");
                }
                return super.put(key, value);
            }
        };
        properties.load(new ByteArrayInputStream(bytes));
        if (keys != null && !properties.stringPropertyNames().equals(keys)) {
            throw denied("ISOLATION_SCHEMA");
        }
        return properties;
    }

    private static Map<String, Object> attributes(Path path) throws IOException {
        return Files.readAttributes(path, "unix:uid,mode,isRegularFile,isDirectory,fileKey,size",
                LinkOption.NOFOLLOW_LINKS);
    }

    private static void checkTrusted(Map<String, Object> attrs, long uid, boolean directory) {
        if (!Boolean.TRUE.equals(attrs.get(directory ? "isDirectory" : "isRegularFile"))
                || ((Number) attrs.get("uid")).longValue() != uid
                || (((Number) attrs.get("mode")).intValue() & 0022) != 0
                || (!directory && ((Number) attrs.get("size")).longValue() > MAX_BYTES)) {
            throw denied("ISOLATION_FILE_TRUST");
        }
    }

    private static void noSymlinkAncestors(Path directory) throws IOException {
        Path current = directory.getRoot();
        for (Path component : directory) {
            current = current.resolve(component);
            if (!Files.readAttributes(current, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS).isDirectory()) {
                throw denied("ISOLATION_PATH");
            }
        }
    }

    private static SecureDirectoryStream<Path> secure(DirectoryStream<Path> stream) {
        if (!(stream instanceof SecureDirectoryStream<?>)) {
            throw denied("ISOLATION_FILESYSTEM");
        }
        @SuppressWarnings("unchecked")
        SecureDirectoryStream<Path> result = (SecureDirectoryStream<Path>) stream;
        return result;
    }

    private static byte[] readTrusted(Path path, long uid) throws IOException {
        Path parent = path.getParent();
        noSymlinkAncestors(parent);
        Map<String, Object> parentAttrs = attributes(parent);
        checkTrusted(parentAttrs, uid, true);
        Map<String, Object> fileAttrs = attributes(path);
        checkTrusted(fileAttrs, uid, false);
        try (DirectoryStream<Path> directory = Files.newDirectoryStream(parent)) {
            SecureDirectoryStream<Path> secure = secure(directory);
            if (!parentAttrs.get("fileKey").equals(secure.getFileAttributeView(
                    BasicFileAttributeView.class).readAttributes().fileKey())) {
                throw denied("ISOLATION_FILE_RACE");
            }
            Path name = path.getFileName();
            BasicFileAttributeView view = secure.getFileAttributeView(name,
                    BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (!fileAttrs.get("fileKey").equals(view.readAttributes().fileKey())) {
                throw denied("ISOLATION_FILE_RACE");
            }
            Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            try (SeekableByteChannel channel = secure.newByteChannel(name, options)) {
                ByteBuffer buffer = ByteBuffer.allocate(MAX_BYTES + 1);
                while (buffer.hasRemaining() && channel.read(buffer) != -1) {
                    // The extra byte detects growth beyond the bounded input contract.
                }
                if (buffer.position() > MAX_BYTES
                        || !fileAttrs.get("fileKey").equals(view.readAttributes().fileKey())) {
                    throw denied("ISOLATION_FILE_RACE");
                }
                return java.util.Arrays.copyOf(buffer.array(), buffer.position());
            }
        }
    }

    private static void writeRequest(Path directory, String nonce, byte[] bytes) throws IOException {
        noSymlinkAncestors(directory);
        Map<String, Object> attrs = attributes(directory);
        if (!Boolean.TRUE.equals(attrs.get("isDirectory"))) {
            throw denied("ISOLATION_REQUEST");
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
            SecureDirectoryStream<Path> secure = secure(stream);
            if (!attrs.get("fileKey").equals(secure.getFileAttributeView(
                    BasicFileAttributeView.class).readAttributes().fileKey())) {
                throw denied("ISOLATION_FILE_RACE");
            }
            Set<OpenOption> options = Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW,
                    LinkOption.NOFOLLOW_LINKS);
            Path pending = Path.of(nonce + ".pending");
            boolean created = false;
            try {
                try (SeekableByteChannel channel = secure.newByteChannel(pending, options,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                    created = true;
                    ByteBuffer buffer = ByteBuffer.wrap(bytes);
                    while (buffer.hasRemaining()) {
                        channel.write(buffer);
                    }
                }
                // Publish a complete challenge with one same-directory secure atomic rename.
                secure.move(pending, secure, Path.of(nonce + ".properties"));
                created = false;
            } finally {
                if (created) {
                    secure.deleteFile(pending);
                }
            }
        }
    }

    private static GateDenied denied(String code) {
        return new GateDenied(code);
    }

    private static final class GateDenied extends IllegalStateException {
        private GateDenied(String code) {
            super(code);
        }
    }
}
