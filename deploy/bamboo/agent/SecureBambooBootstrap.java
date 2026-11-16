package com.mellivora.bamboo;

import com.atlassian.bamboo.agent.AgentType;
import com.atlassian.bamboo.agent.AgentTypeHolder;
import com.atlassian.bamboo.agent.bootstrap.RemoteAgentBootstrap;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Map;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;

/** Fixed-server, same-JVM bootstrap. Never delegates credentials to the native wrapper. */
public final class SecureBambooBootstrap {
    static final String ENDPOINT = "https://deploy.mellivora.com.cn/agentServer/";
    private static final int MAX_CREDENTIAL_BYTES = 4096;
    private static final Path NATIVE_CREDENTIAL = Path.of(
            "/run/credentials/bamboo-agent.service/security-token");

    private SecureBambooBootstrap() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Exactly one protected credential-file path is required");
        }
        launch(new URL(ENDPOINT), Path.of(args[0]));
    }

    // Package-private for an isolated test harness; production CLI cannot override the server.
    static void launch(URL endpoint, Path credential) throws Exception {
        String token = readToken(credential);
        List<String> forms = new ArrayList<>();
        forms.add(token);
        String encoded = URLEncoder.encode(token, StandardCharsets.UTF_8);
        if (!encoded.equals(token)) forms.add(encoded);
        if (encoded.indexOf('%') >= 0) {
            StringBuilder lowerHex = new StringBuilder(encoded);
            for (int i = 0; i + 2 < lowerHex.length(); i++) {
                if (lowerHex.charAt(i) == '%') {
                    lowerHex.setCharAt(i + 1, Character.toLowerCase(lowerHex.charAt(i + 1)));
                    lowerHex.setCharAt(i + 2, Character.toLowerCase(lowerHex.charAt(i + 2)));
                    i += 2;
                }
            }
            String lowercaseEncoding = lowerHex.toString();
            if (!forms.contains(lowercaseEncoding)) forms.add(lowercaseEncoding);
        }
        Pattern[] patterns = new Pattern[forms.size()];
        for (int i = 0; i < forms.size(); i++) patterns[i] = new Pattern(forms.get(i));
        RedactingStream stdout = new RedactingStream(System.out, patterns);
        RedactingStream stderr = new RedactingStream(System.err, patterns);
        System.setOut(new PrintStream(stdout, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(stderr, true, StandardCharsets.UTF_8));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { stdout.finish(); stderr.finish(); } catch (IOException ignored) { /* JVM is exiting. */ }
        }, "bamboo-log-redaction-flush"));
        VendorRunner.start(endpoint, token);
    }

    static String readToken(Path credential) throws IOException {
        var attributes = Files.readAttributes(credential,
                "unix:uid,gid,mode,nlink,isRegularFile", LinkOption.NOFOLLOW_LINKS);
        if (!Boolean.TRUE.equals(attributes.get("isRegularFile"))) {
            throw new IOException("Protected credential file is not regular");
        }
        if (credential.equals(NATIVE_CREDENTIAL)) {
            validateNativeCredential(credential, attributes);
        } else {
            for (PosixFilePermission permission : Files.getPosixFilePermissions(
                    credential, LinkOption.NOFOLLOW_LINKS)) {
                if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_")) {
                    throw new IOException("Credential file must not grant group or other access");
                }
            }
        }
        byte[] bytes;
        try (InputStream input = Files.newInputStream(credential, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(MAX_CREDENTIAL_BYTES + 1);
        }
        if (bytes.length == 0 || bytes.length > MAX_CREDENTIAL_BYTES) {
            Arrays.fill(bytes, (byte) 0);
            throw new IOException("Credential length is invalid");
        }
        String token = new String(bytes, StandardCharsets.UTF_8).strip();
        Arrays.fill(bytes, (byte) 0);
        if (token.length() < 16) {
            throw new IOException("Credential must contain at least16 characters");
        }
        // AgentContext concatenates the value into a URI without encoding it.
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~')) {
                throw new IOException("Credential contains a character unsupported by vendor URI transport");
            }
        }
        return token;
    }

    /** systemd's root-owned, read-only credential mount grants the service access through an ACL. */
    private static void validateNativeCredential(Path credential, Map<String, Object> attributes)
            throws IOException {
        int mode = ((Integer) attributes.get("mode")) & 07777;
        if (!Integer.valueOf(0).equals(attributes.get("uid"))
                || !Integer.valueOf(0).equals(attributes.get("gid"))
                || !Integer.valueOf(1).equals(attributes.get("nlink"))
                || (mode != 0400 && mode != 0440)) {
            throw new IOException("Native credential ownership or permissions are unsafe");
        }
        Path directory = credential.getParent();
        for (Path ancestor = directory; ancestor != null; ancestor = ancestor.getParent()) {
            var parent = Files.readAttributes(ancestor,
                    "unix:uid,gid,mode,isDirectory", LinkOption.NOFOLLOW_LINKS);
            int permissions = ((Integer) parent.get("mode")) & 07777;
            if (!Boolean.TRUE.equals(parent.get("isDirectory"))
                    || !Integer.valueOf(0).equals(parent.get("uid"))
                    || !Integer.valueOf(0).equals(parent.get("gid"))
                    || (permissions & 07022) != 0
                    || (ancestor.equals(directory) && permissions != 0500 && permissions != 0550)) {
                throw new IOException("Native credential directory is unsafe");
            }
        }
        var store = Files.getFileStore(directory);
        if (!store.isReadOnly() || !store.type().equals("tmpfs")
                || !Files.getAttribute(credential, "unix:dev", LinkOption.NOFOLLOW_LINKS).equals(
                        Files.getAttribute(directory, "unix:dev", LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("Native credential must reside on its read-only systemd mount");
        }
    }

    /** Loaded only after both process streams have their secret filters installed. */
    private static final class VendorRunner extends RemoteAgentBootstrap {
        private VendorRunner(URL endpoint, String token) { super(endpoint, token); }

        static void start(URL endpoint, String token) {
            AgentTypeHolder.set(AgentType.REMOTE);
            configureLogging();
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            var appenders = context.getConfiguration().getAppenders().values();
            if (appenders.isEmpty()) {
                throw new IllegalStateException("Only filtered console logging is permitted");
            }
            for (var appender : appenders) {
                if (!(appender instanceof ConsoleAppender)) {
                    throw new IllegalStateException("Only filtered console logging is permitted");
                }
            }
            new VendorRunner(endpoint, token).run(AgentType.REMOTE);
        }
    }

    /** Immutable KMP tables shared by the independent stdout and stderr filters. */
    static final class Pattern {
        final byte[] bytes;
        final int[] failure;

        Pattern(String value) {
            bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length == 0) throw new IllegalArgumentException("Empty redaction pattern");
            failure = new int[bytes.length];
            for (int i = 1, matched = 0; i < bytes.length; i++) {
                while (matched > 0 && bytes[i] != bytes[matched]) matched = failure[matched - 1];
                if (bytes[i] == bytes[matched]) matched++;
                failure[i] = matched;
            }
        }
    }

    /** Bounded streaming redaction, including matches split across writes and flush calls. */
    static final class RedactingStream extends OutputStream {
        private static final byte[] REPLACEMENT = " [REDACTED] ".getBytes(StandardCharsets.US_ASCII);
        private final OutputStream output;
        private final Pattern[] patterns;
        private final int[] matched;
        private final byte[] pending;
        private int head;
        private int count;

        RedactingStream(OutputStream output, Pattern[] patterns) {
            this.output = new BufferedOutputStream(output, 8192);
            this.patterns = patterns;
            matched = new int[patterns.length];
            int maximum = 0;
            for (Pattern pattern : patterns) maximum = Math.max(maximum, pattern.bytes.length);
            pending = new byte[maximum + 1];
        }

        @Override public synchronized void write(int value) throws IOException {
            writeByte((byte) value);
        }

        private void writeByte(byte current) throws IOException {
            pending[(head + count) % pending.length] = current;
            count++;
            int full = 0;
            int retained = 0;
            for (int i = 0; i < patterns.length; i++) {
                Pattern pattern = patterns[i];
                int length = matched[i];
                while (length > 0 && current != pattern.bytes[length]) length = pattern.failure[length - 1];
                if (current == pattern.bytes[length]) length++;
                matched[i] = length;
                if (length == pattern.bytes.length) full = Math.max(full, length);
                retained = Math.max(retained, length);
            }
            if (full > 0) {
                emit(count - full);
                output.write(REPLACEMENT);
                head = 0;
                count = 0;
                Arrays.fill(matched, 0);
            } else {
                emit(count - retained);
            }
        }

        @Override public synchronized void write(byte[] bytes, int offset, int length) throws IOException {
            java.util.Objects.checkFromIndexSize(offset, length, bytes.length);
            for (int i = offset; i < offset + length; i++) writeByte(bytes[i]);
        }

        private void emit(int length) throws IOException {
            if (length == 0) return;
            int first = Math.min(length, pending.length - head);
            output.write(pending, head, first);
            if (first < length) output.write(pending, 0, length - first);
            head = (head + length) % pending.length;
            count -= length;
        }

        @Override public synchronized void flush() throws IOException {
            // A partial secret prefix remains private until disambiguated or final close.
            output.flush();
        }

        synchronized void finish() throws IOException {
            emit(count);
            Arrays.fill(matched, 0);
            output.flush();
        }

        @Override public void close() throws IOException { finish(); }
    }
}
