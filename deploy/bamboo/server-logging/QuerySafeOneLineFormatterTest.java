package com.mellivora.bamboo.logging;

import java.time.Instant;
import java.util.Arrays;
import java.util.ListResourceBundle;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.apache.juli.OneLineFormatter;

/** Standalone checks against the real tomcat-juli.jar; no network or real credentials. */
public final class QuerySafeOneLineFormatterTest {
    private static final String RAW_ONE = "privateSyntheticRawOne_83f2";
    private static final String RAW_TWO = "privateSyntheticRawTwo_46c1";
    private static final String ENCODED_ONE = "privateSyntheticEncodedOne_7bd3";
    private static final String ENCODED_TWO = "privateSyntheticEncodedTwo_51a9";
    private static final String[] PRIVATE_MARKERS = {RAW_ONE, RAW_TWO, ENCODED_ONE, ENCODED_TWO};
    private static final QuerySafeOneLineFormatter SAFE = new QuerySafeOneLineFormatter();
    private static final OneLineFormatter NATIVE = new OneLineFormatter();

    private QuerySafeOneLineFormatterTest() {
    }

    private static void check(boolean condition, String diagnostic) {
        // Only static, non-secret descriptions reach assertion output, never rendered logs.
        if (!condition) throw new AssertionError(diagnostic);
    }

    private static void retained(String output, String... usefulMarkers) {
        for (String marker : usefulMarkers) {
            check(output.contains(marker), "Useful diagnostic context was removed");
        }
    }

    private static void privateValuesAbsent(String output) {
        for (String marker : PRIVATE_MARKERS) {
            check(!output.contains(marker), "A private synthetic query value survived rendering");
        }
    }

    private static LogRecord record(String message) {
        LogRecord record = new LogRecord(Level.WARNING, message);
        record.setInstant(Instant.parse("2026-11-13T12:34:56.123Z"));
        record.setSequenceNumber(17L);
        record.setLongThreadID(Thread.currentThread().threadId());
        record.setLoggerName("org.apache.catalina.valves.StuckThreadDetectionValve");
        record.setSourceClassName("org.apache.catalina.valves.StuckThreadDetectionValve");
        record.setSourceMethodName("notifyStuckThreadDetected");
        return record;
    }

    private static void parameterRenderingAndRecordRetention() {
        String template = "DIAG-STUCK status={0} elapsed={1} request={2} worker={3}";
        String url = "https://bamboo.example.invalid/agentServer/GetFingerprint.action?securityToken="
                + RAW_ONE + "&agentUuid=agent-visible&securityToken=" + RAW_TWO + "&retry=2";
        Object[] parameters = {503, "60s", url, "worker-visible"};
        Object[] originalParameters = parameters.clone();
        LogRecord input = record(template);
        input.setParameters(parameters);
        String nativeOutput = NATIVE.format(input);
        retained(nativeOutput, RAW_ONE, RAW_TWO, "status=503", "elapsed=60s");

        String output = SAFE.format(input);
        privateValuesAbsent(output);
        retained(output, "DIAG-STUCK", "status=503", "elapsed=60s",
                "https://bamboo.example.invalid/agentServer/GetFingerprint.action?securityToken=",
                "&agentUuid=agent-visible&securityToken=", "&retry=2", "worker=worker-visible",
                "StuckThreadDetectionValve", "notifyStuckThreadDetected");
        check(input.getMessage() == template, "Original message reference changed");
        check(input.getParameters() == parameters, "Original parameter array reference changed");
        check(Arrays.equals(originalParameters, parameters), "Original parameter contents changed");
        check(input.getThrown() == null, "Unexpected throwable added to record");
        check(input.getLevel() == Level.WARNING && input.getSequenceNumber() == 17L,
                "Record metadata changed");
        check(input.getInstant().equals(Instant.parse("2026-11-13T12:34:56.123Z")),
                "Record timestamp changed");
        check(NATIVE.format(input).equals(nativeOutput), "Native rendering changed after safe rendering");
    }

    private static void encodedAndRepeatedFields() {
        String encoded = "DIAG-ENCODED status=502 request=/agentServer/GetFingerprint.action"
                + "%3FsecurityToken%3D" + ENCODED_ONE
                + "%26agentUuid%3Dencoded-visible%26securityToken%3D" + ENCODED_TWO
                + "%26retry%3D3 context=encoded-tail";
        String lowerCase = "DIAG-LOWER request=/agentServer/GetFingerprint.action"
                + "%3fsecurityToken%3d" + ENCODED_TWO + "%26status%3d504 context=lower-tail";
        String raw = "DIAG-RAW request=/agentServer/GetFingerprint.action?securityToken="
                + RAW_ONE + "&status=503 tail=raw-tail";
        String output = SAFE.format(record(encoded + "\n" + lowerCase + "\n" + raw));
        privateValuesAbsent(output);
        retained(output, "DIAG-ENCODED", "status=502", "/agentServer/GetFingerprint.action",
                "%3FsecurityToken%3D", "%26agentUuid%3Dencoded-visible%26securityToken%3D",
                "%26retry%3D3", "context=encoded-tail", "DIAG-LOWER", "%3fsecurityToken%3d",
                "%26status%3d504", "context=lower-tail", "DIAG-RAW", "&status=503", "tail=raw-tail");
    }

    private static void throwableRenderingAndRetention() {
        IllegalArgumentException cause = new IllegalArgumentException(
                "DIAG-CAUSE request=/cause?securityToken=" + RAW_TWO + "&status=401 原因保持");
        cause.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("UsefulCauseFrame", "diagnose", "UsefulCauseFrame.java", 42)
        });
        IllegalStateException suppressed = new IllegalStateException(
                "DIAG-SUPPRESSED request=/suppressed%3FsecurityToken%3D" + ENCODED_ONE
                        + "%26status%3D502 suppressed-tail");
        suppressed.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("UsefulSuppressedFrame", "cleanup", "UsefulSuppressedFrame.java", 53)
        });
        RuntimeException failure = new RuntimeException(
                "DIAG-FAILURE request=/failure?securityToken=" + RAW_ONE + "&status=503 failure-tail", cause);
        failure.addSuppressed(suppressed);
        // A stack element itself is rendered by Throwable, not LogRecord message formatting.
        failure.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("UsefulFailureFrame", "request",
                        "Trace.java?securityToken=" + ENCODED_TWO + "&trace=visible", 64)
        });
        LogRecord input = record("DIAG-WARNING 请求超时；线程诊断保留 status=503 context=warning-tail");
        input.setThrown(failure);
        String message = input.getMessage();
        String failureMessage = failure.getMessage();
        String causeMessage = cause.getMessage();
        String suppressedMessage = suppressed.getMessage();
        StackTraceElement[] originalFailureStack = failure.getStackTrace();
        StackTraceElement[] originalCauseStack = cause.getStackTrace();
        StackTraceElement[] originalSuppressedStack = suppressed.getStackTrace();
        String nativeOutput = NATIVE.format(input);
        retained(nativeOutput, RAW_ONE, RAW_TWO, ENCODED_ONE, ENCODED_TWO);

        String output = SAFE.format(input);
        privateValuesAbsent(output);
        retained(output, "DIAG-WARNING", "请求超时；线程诊断保留", "context=warning-tail",
                "java.lang.RuntimeException", "DIAG-FAILURE", "/failure?securityToken=", "&status=503",
                "failure-tail", "Caused by:", "java.lang.IllegalArgumentException", "DIAG-CAUSE",
                "/cause?securityToken=", "&status=401", "原因保持", "Suppressed:",
                "java.lang.IllegalStateException", "DIAG-SUPPRESSED", "/suppressed%3FsecurityToken%3D",
                "%26status%3D502", "suppressed-tail", "UsefulFailureFrame.request",
                "Trace.java?securityToken=", "&trace=visible:64", "UsefulCauseFrame.diagnose",
                "UsefulCauseFrame.java:42", "UsefulSuppressedFrame.cleanup", "UsefulSuppressedFrame.java:53");
        check(input.getMessage() == message && input.getThrown() == failure,
                "Original record message or throwable reference changed");
        check(failure.getMessage() == failureMessage && cause.getMessage() == causeMessage
                        && suppressed.getMessage() == suppressedMessage,
                "Original throwable message changed");
        check(failure.getCause() == cause && failure.getSuppressed().length == 1
                        && failure.getSuppressed()[0] == suppressed,
                "Original throwable graph changed");
        check(Arrays.equals(originalFailureStack, failure.getStackTrace())
                        && Arrays.equals(originalCauseStack, cause.getStackTrace())
                        && Arrays.equals(originalSuppressedStack, suppressed.getStackTrace()),
                "Original throwable stack changed");
        check(NATIVE.format(input).equals(nativeOutput), "Native throwable rendering changed after redaction");
    }

    private static void ordinaryAndLocalizedDiagnostics() {
        LogRecord ordinary = record("DIAG-NORMAL 用户配置未改 status=504 path=/agentServer/health context=保留");
        check(SAFE.format(ordinary).equals(NATIVE.format(ordinary)), "Ordinary warning rendering changed");
        LogRecord localized = record("localized.warning");
        ResourceBundle bundle = new ListResourceBundle() {
            @Override
            protected Object[][] getContents() {
                return new Object[][] {{"localized.warning", "DIAG-LOCALIZED 请求={0} status={1} 诊断保留"}};
            }
        };
        Object[] parameters = {"/localized?securityToken=" + RAW_ONE + "&agentUuid=localized-visible", 503};
        localized.setResourceBundle(bundle);
        localized.setResourceBundleName("synthetic.diagnostics");
        localized.setParameters(parameters);
        String output = SAFE.format(localized);
        privateValuesAbsent(output);
        retained(output, "DIAG-LOCALIZED", "请求=/localized?securityToken=", "&agentUuid=localized-visible",
                "status=503", "诊断保留");
        check(localized.getResourceBundle() == bundle && localized.getParameters() == parameters
                        && localized.getMessage().equals("localized.warning"),
                "Localized record contents changed");
    }

    public static void main(String[] args) {
        parameterRenderingAndRecordRetention();
        encodedAndRepeatedFields();
        throwableRenderingAndRetention();
        ordinaryAndLocalizedDiagnostics();
        System.out.println("PASS: actual JULI parameters, repeated raw/encoded queries, throwable graph, Unicode, localization and non-mutation");
    }
}
