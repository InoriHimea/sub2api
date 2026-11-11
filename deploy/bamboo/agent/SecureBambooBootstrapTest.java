package com.mellivora.bamboo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/** Standalone deterministic checks; no real credentials, network or Bamboo enrollment. */
public final class SecureBambooBootstrapTest {
    private static final String SECRET = "fixture-token-20261111+/=";

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("Unexpected redaction result");
    }

    private static String redact(String text, int fragment) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        var patterns = new SecureBambooBootstrap.Pattern[] {
            new SecureBambooBootstrap.Pattern(SECRET),
            new SecureBambooBootstrap.Pattern("fixture-token-20261111%2B%2F%3D"),
            new SecureBambooBootstrap.Pattern("fixture-token-20261111%2b%2f%3d")
        };
        var stream = new SecureBambooBootstrap.RedactingStream(output, patterns);
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        for (int offset = 0; offset < bytes.length; offset += fragment) {
            stream.write(bytes, offset, Math.min(fragment, bytes.length - offset));
            stream.flush();
        }
        stream.finish();
        return output.toString(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String message = "HTTP401 request /fingerprint?securityToken=" + SECRET + "&agentUuid=test\n";
        String expected = "HTTP401 request /fingerprint?securityToken= [REDACTED] &agentUuid=test\n";
        for (int fragment : new int[] {1, 2, 7, 8192}) equal(expected, redact(message, fragment));

        equal(" [REDACTED] | [REDACTED] | [REDACTED] ", redact(
                SECRET + "|fixture-token-20261111%2B%2F%3D|fixture-token-20261111%2b%2f%3d", 1));
        equal(" [REDACTED]  [REDACTED] ", redact(SECRET + SECRET, 3));
        String ordinary = "Diagnosis: TLS handshake failed; 用户配置未改; endpoint=localhost\n";
        equal(ordinary, redact(ordinary, 1));
        equal("fixture-token-2026111", redact("fixture-token-2026111", 4));
        String large = ("prefix " + SECRET + " suffix\n").repeat(10000);
        equal(("prefix  [REDACTED]  suffix\n").repeat(10000), redact(large, 13));

        // KMP fallback must not discard an ordinary prefix that shares secret bytes.
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        var overlap = new SecureBambooBootstrap.RedactingStream(output,
                new SecureBambooBootstrap.Pattern[] {new SecureBambooBootstrap.Pattern("ababaca")});
        overlap.write("ababababaca!".getBytes(StandardCharsets.US_ASCII));
        overlap.finish();
        equal("abab [REDACTED] !", output.toString(StandardCharsets.US_ASCII));

        Path root = Files.createTempDirectory("bamboo-credential-test-");
        try {
            try {
                SecureBambooBootstrap.launch(new URL("http://127.0.0.1:1/"), root.resolve("missing"));
                throw new AssertionError("Missing credentials accepted");
            } catch (IOException expectedFailure) {
                equal("Protected credential file is missing or not regular", expectedFailure.getMessage());
            }
            Path credential = root.resolve("credential");
            Files.writeString(credential, SECRET);
            Files.setPosixFilePermissions(credential, PosixFilePermissions.fromString("rw-r-----"));
            try {
                SecureBambooBootstrap.launch(new URL("http://127.0.0.1:1/"), credential);
                throw new AssertionError("Shared credentials accepted");
            } catch (IOException expectedFailure) {
                equal("Credential file must not grant group or other access", expectedFailure.getMessage());
            }
            Files.setPosixFilePermissions(credential, PosixFilePermissions.fromString("rw-------"));
            try {
                SecureBambooBootstrap.launch(new URL("http://127.0.0.1:1/"), credential);
                throw new AssertionError("Unsafe URI credential accepted");
            } catch (IOException expectedFailure) {
                equal("Credential contains a character unsupported by vendor URI transport", expectedFailure.getMessage());
            }
            Files.delete(credential);
        } finally {
            Files.delete(root);
        }
        System.out.println("PASS: fragmented/raw/encoded/adjacent/unicode/overlap/large-log and credential boundaries");
    }
}
