package com.mellivora.bamboo.logging;

/** Standalone deterministic regression driver; throws on the first mismatch. */
public final class SecurityTokenQueryRedactorTest {
    private static int assertions;

    private SecurityTokenQueryRedactorTest() {
    }

    public static void main(String[] args) {
        normalDiagnostics();
        rawAssignments();
        encodedAssignments();
        boundariesAndMalformedNames();
        delimiterMatrix();
        encodingMatrix();
        largeDiagnostic();
        System.out.println("SecurityTokenQueryRedactorTest: " + assertions + " assertions passed");
    }

    private static void normalDiagnostics() {
        unchanged("");
        unchanged("WARN request /agentServer/GetFingerprint.action failed: java.io.IOException\n\tat example.run(Example.java:42)");
        unchanged("警告: 请求失败 — диагностика محفوظة 😀");
        unchanged("/path/securityToken?other=visible&token=unrelated#fragment");
        unchanged("securityToken");
        unchanged("securityToken=");
        unchanged("?securityToken=&agentUuid=public");
        unchanged("securityToken%3D%26agentUuid%3Dpublic");
        unchanged("securityToken%253D%2526agentUuid%253Dpublic");
        unchanged("securityToken=[REDACTED]");
        // Unlabeled standalone tokens are deliberately outside this finite contract.
        unchanged("Transport rejected Abc-._~123; no field name was rendered");
    }

    private static void rawAssignments() {
        check("securityToken=Abc-._~123", "securityToken=[REDACTED]");
        check("WARN /agentServer/GetFingerprint.action?securityToken=private-value&agentUuid=public-id status=500",
                "WARN /agentServer/GetFingerprint.action?securityToken=[REDACTED]&agentUuid=public-id status=500");
        check("?SECURITYTOKEN=one&SecurityToken=two&securityToken=&other=retained",
                "?SECURITYTOKEN=[REDACTED]&SecurityToken=[REDACTED]&securityToken=&other=retained");
        check("?securityToken=secret#diagnostic-fragment", "?securityToken=[REDACTED]#diagnostic-fragment");
        check("警告 ?securityToken=private&other=保留 😀\njava.io.IOException: 接続失敗\n\tat demo.Run.run(Run.java:9)",
                "警告 ?securityToken=[REDACTED]&other=保留 😀\njava.io.IOException: 接続失敗\n\tat demo.Run.run(Run.java:9)");
        check("request='?securityToken=secret' failed (IOException)",
                "request='?securityToken=[REDACTED]' failed (IOException)");
        check("securityToken=secret%", "securityToken=[REDACTED]");
        check("securityToken=secret%2", "securityToken=[REDACTED]");
        check("securityToken=secret%QZ&keep=yes", "securityToken=[REDACTED]&keep=yes");
        // Conservative known false positives: no URL parser distinguishes these assignments.
        check("Configuration example: securityToken=example-value, not a request",
                "Configuration example: securityToken=[REDACTED], not a request");
        check("other=securityToken=example-value", "other=securityToken=[REDACTED]");
    }

    private static void encodedAssignments() {
        check("%3FsecurityToken%3Dsecret%26agentUuid%3Dpublic",
                "%3FsecurityToken%3D[REDACTED]%26agentUuid%3Dpublic");
        check("%253fsecurityToken%253dsecret%2526agentUuid%253dpublic",
                "%253fsecurityToken%253d[REDACTED]%2526agentUuid%253dpublic");
        check("?%73e%63urity%54oken=secret&keep=yes", "?%73e%63urity%54oken=[REDACTED]&keep=yes");
        check("?%2573e%2563urity%2554oken%253Dsecret%2526keep%253Dyes",
                "?%2573e%2563urity%2554oken%253D[REDACTED]%2526keep%253Dyes");
        check("securityToken=foo%26bar%20baz%23fragment&keep=yes",
                "securityToken=[REDACTED]&keep=yes");
        check("securityToken%3Dfoo%2526bar%26keep%3Dyes",
                "securityToken%3D[REDACTED]%26keep%3Dyes");
        check("securityToken%253Dfoo%26bar%2526keep%253Dyes",
                "securityToken%253D[REDACTED]%2526keep%253Dyes");
        check("securityToken%3Dfoo%23fragment", "securityToken%3D[REDACTED]%23fragment");
        check("securityToken%253Dfoo%2523fragment", "securityToken%253D[REDACTED]%2523fragment");
        check("?securityToken=one%26securityToken%3Dtwo&securityToken=three",
                "?securityToken=[REDACTED]&securityToken=[REDACTED]");
        check("securityToken%3Dsecret&keep=raw", "securityToken%3D[REDACTED]&keep=raw");
    }

    private static void boundariesAndMalformedNames() {
        String[] prefixes = {"my", "x", "_", "-", ".", "7", "é", "%78", "%2578", "%", "%25"};
        for (String prefix : prefixes) {
            unchanged(prefix + "securityToken=not-a-token-field&keep=yes");
        }
        String[] invalidNames = {
                "securityTokens", "securityTokenExtra", "securityToken_", "securityToken-",
                "securityToken.", "securityToken%", "securityToken%3", "securityToken%GG",
                "securitToken", "security Token", "security+Token", "security%20Token",
                "%2573ecurityToken%25253D", "%252573ecurityToken", "securityToken&#61;"
        };
        for (String name : invalidNames) {
            unchanged("?" + name + "=ordinary&keep=yes");
        }
        unchanged("securityToken%25253Doutside-contract");
        unchanged("securityToken&#61;outside-contract");
        check("?securityToken=one&mySecurityToken=keep&securityToken=two",
                "?securityToken=[REDACTED]&mySecurityToken=keep&securityToken=[REDACTED]");
        check("securityToken=one\nsecurityToken=two", "securityToken=[REDACTED]\nsecurityToken=[REDACTED]");
    }

    private static void delimiterMatrix() {
        String delimiters = "& \t\r\n\f\u2003\u00a0\"'<>[](){},;#";
        for (int index = 0; index < delimiters.length(); index++) {
            char delimiter = delimiters.charAt(index);
            for (int separatorDepth = 0; separatorDepth <= 2; separatorDepth++) {
                String separator = encode('=', separatorDepth);
                String tail = delimiter + "diagnostic";
                check("securityToken" + separator + "private" + tail,
                        "securityToken" + separator + "[REDACTED]" + tail);
                unchanged("securityToken" + separator + tail);
                if (delimiter <= 127) {
                    for (int delimiterDepth = 1; delimiterDepth <= 2; delimiterDepth++) {
                        String encodedTail = encode(delimiter, delimiterDepth) + "diagnostic";
                        String expectedTail = separatorDepth == delimiterDepth ? encodedTail : "";
                        check("securityToken" + separator + "private" + encodedTail,
                                "securityToken" + separator + "[REDACTED]" + expectedTail);
                    }
                }
            }
        }
    }

    private static void encodingMatrix() {
        // Every name position independently gets raw, single, or double encoding.
        String field = "sEcUrItYtOkEn";
        for (int encodedPosition = 0; encodedPosition < field.length(); encodedPosition++) {
            for (int nameDepth = 0; nameDepth <= 2; nameDepth++) {
                String name = field.substring(0, encodedPosition)
                        + encode(field.charAt(encodedPosition), nameDepth)
                        + field.substring(encodedPosition + 1);
                for (int separatorDepth = 0; separatorDepth <= 2; separatorDepth++) {
                    String prefix = "%3f" + name + encode('=', separatorDepth);
                    check(prefix + "private&keep=yes", prefix + "[REDACTED]&keep=yes");
                }
            }
        }
        for (int depth = 1; depth <= 2; depth++) {
            StringBuilder name = new StringBuilder();
            for (int index = 0; index < field.length(); index++) {
                name.append(encode(field.charAt(index), depth));
            }
            String prefix = encode('?', depth) + name + encode('=', depth);
            String suffix = encode('&', depth) + "keep" + encode('=', depth) + "yes";
            check(prefix + "private" + suffix, prefix + "[REDACTED]" + suffix);
        }
    }

    private static void largeDiagnostic() {
        String ordinary = "securityTokeX%25 malformed ?other=visible 警告\n".repeat(4096);
        unchanged(ordinary);
        check(ordinary + "?securityToken=" + "A-._~123".repeat(4096) + "&keep=visible\n" + ordinary,
                ordinary + "?securityToken=[REDACTED]&keep=visible\n" + ordinary);
        String repeated = "?securityToken=private&keep=yes\n".repeat(1024);
        check(repeated, "?securityToken=[REDACTED]&keep=yes\n".repeat(1024));
    }

    private static String encode(char character, int depth) {
        if (depth == 0) {
            return String.valueOf(character);
        }
        String digits = "0123456789abcdef";
        return (depth == 1 ? "%" : "%25")
                + digits.charAt(character >>> 4) + digits.charAt(character & 15);
    }

    private static void unchanged(String input) {
        String actual = SecurityTokenQueryRedactor.redact(input);
        assertions++;
        if (!java.util.Objects.equals(actual, input)) {
            throw new AssertionError("Ordinary diagnostic text changed");
        }
    }

    private static void check(String input, String expected) {
        String actual = SecurityTokenQueryRedactor.redact(input);
        assertions++;
        if (!expected.equals(actual)) {
            throw new AssertionError("Input: " + input + "\nExpected: " + expected + "\nActual: " + actual);
        }
    }
}
