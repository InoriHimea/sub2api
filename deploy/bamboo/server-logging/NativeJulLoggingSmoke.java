package com.mellivora.bamboo.logging;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.StuckThreadDetectionValve;
import org.apache.catalina.valves.ValveBase;

import jakarta.servlet.ServletException;

/** Actual native valve/handlers and startup policy; synthetic inputs only, no HTTP listener. */
public final class NativeJulLoggingSmoke {
    private static final String RAW = "CD08_PRIVATE_NATIVE_RAW_20261113";
    private static final String ERROR = "CD08_PRIVATE_NATIVE_ERROR_20261113";
    private static final String CAUSE = "CD08_PRIVATE_NATIVE_CAUSE_20261113";
    private static final String ENCODED = "CD08_PRIVATE_NATIVE_ENCODED_20261113";
    private static final String PROBE = "com.mellivora.bamboo.logging.startupGuard";

    private NativeJulLoggingSmoke() {}

    private static void check(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }

    private static boolean complete(String text) {
        return text.contains("/agentServer/GetFingerprint.action?securityToken=[REDACTED]&agentUuid=visible-native")
                && text.contains("QUERYSAFE_ERROR status=503")
                && text.contains("QUERYSAFE_PARAMETERS status=502")
                && text.contains("QUERYSAFE_ENCODED")
                && text.contains("QUERYSAFE_UNICODE 请求诊断保留")
                && text.contains("Caused by:") && text.contains("Suppressed:");
    }

    private static void verifyDiagnostic(String text) {
        for (String value : List.of(RAW, ERROR, CAUSE, ENCODED)) {
            check(!text.contains(value), "Synthetic credential survived a native handler");
        }
        check(complete(text), "Native handler lost diagnostic records or request context");
        check(text.contains("UsefulCauseFrame.diagnose") && text.contains("UsefulSuppressedFrame.cleanup"),
                "Useful throwable stack frames lost");
        check(text.contains("%3FsecurityToken%3D[REDACTED]%26agentUuid%3Dvisible-encoded"),
                "Encoded URL path or other parameters lost");
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "Expected owned output directory");
        Path root = Path.of(args[0]);
        // Negative startup cases must fail before the application can create this marker.
        Files.writeString(root.resolve("application-started"), "started\n", StandardCharsets.UTF_8);
        LogManager manager = LogManager.getLogManager();
        Handler[] handlers = Logger.getLogger(PROBE).getHandlers();
        check(handlers.length == 7, "Expected five prefixed async, one direct and one console handler");
        for (Handler handler : handlers) {
            check(handler.getFormatter().getClass() == QuerySafeOneLineFormatter.class,
                    "Native handler silently fell back to another formatter");
        }

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();
        Thread worker = null;
        ClassLoader originalLoader = Thread.currentThread().getContextClassLoader();
        try (URLClassLoader commonLoader = new URLClassLoader(new URL[0], originalLoader)) {
            // Tomcat changes context classloader after JVM startup. Exercise native JULI inheritance.
            Thread.currentThread().setContextClassLoader(commonLoader);
            StuckThreadDetectionValve valve = new StuckThreadDetectionValve();
            valve.setThreshold(1);
            valve.setNext(new ValveBase(true) {
                @Override
                public void invoke(Request request, Response response) throws IOException, ServletException {
                    entered.countDown();
                    try {
                        if (!release.await(10, TimeUnit.SECONDS)) throw new IOException("Fixture release timed out");
                    } catch (InterruptedException failure) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Fixture interrupted", failure);
                    }
                }
            });
            Request request = new Request(new Connector()) {
                @Override
                public StringBuffer getRequestURL() {
                    return new StringBuffer("http://fixture.invalid/agentServer/GetFingerprint.action");
                }

                @Override
                public String getQueryString() {
                    return "securityToken=" + RAW + "&agentUuid=visible-native";
                }
            };
            Response response = new Response();
            worker = new Thread(() -> {
                try {
                    valve.invoke(request, response);
                } catch (Throwable failure) {
                    workerFailure.set(failure);
                }
            }, "querysafe-native-stuck");
            worker.start();
            check(entered.await(5, TimeUnit.SECONDS), "Actual native valve did not enter controlled request");
            Thread.sleep(1300);
            valve.backgroundProcess();

            Logger logger = Logger.getLogger("querysafe.native.diagnostics");
            IllegalArgumentException cause = new IllegalArgumentException(
                    "QUERYSAFE_CAUSE /cause?securityToken=" + CAUSE + "&status=401");
            cause.setStackTrace(new StackTraceElement[] {
                    new StackTraceElement("UsefulCauseFrame", "diagnose", "Cause.java", 42)
            });
            IOException suppressed = new IOException("QUERYSAFE_SUPPRESSED /suppressed?securityToken=" + ERROR);
            suppressed.setStackTrace(new StackTraceElement[] {
                    new StackTraceElement("UsefulSuppressedFrame", "cleanup", "Cleanup.java", 53)
            });
            RuntimeException failure = new RuntimeException(
                    "QUERYSAFE_FAILURE /failure?securityToken=" + ERROR + "&status=503", cause);
            failure.addSuppressed(suppressed);
            logger.log(Level.SEVERE, "QUERYSAFE_ERROR status=503 /error?securityToken=" + ERROR, failure);
            logger.log(Level.WARNING, "QUERYSAFE_PARAMETERS status={0} request={1}",
                    new Object[] {502, "/parameter?securityToken=" + ERROR + "&agentUuid=visible-parameter"});
            logger.warning("QUERYSAFE_ENCODED /encoded%3FsecurityToken%3D" + ENCODED
                    + "%26agentUuid%3Dvisible-encoded");
            logger.warning("QUERYSAFE_UNICODE 请求诊断保留 status=504 path=/ordinary");

            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            List<Path> files;
            while (true) {
                for (Handler handler : handlers) handler.flush();
                try (var listing = Files.list(root.resolve("logs"))) {
                    files = listing.filter(Files::isRegularFile).toList();
                }
                boolean ready = files.size() == 6;
                if (ready) {
                    for (Path file : files) {
                        if (!complete(Files.readString(file, StandardCharsets.UTF_8))) ready = false;
                    }
                }
                if (ready) break;
                check(System.nanoTime() < deadline, "Native async handlers did not preserve all diagnostics");
                Thread.sleep(10);
            }
            for (Path file : files) verifyDiagnostic(Files.readString(file, StandardCharsets.UTF_8));
            check(QuerySafeOneLineFormatter.class.getClassLoader() == ClassLoader.getSystemClassLoader(),
                    "Premain JAR was not visible from system classloader");
            System.out.println("{\"native_stuck_warning_redacted\":true,\"native_file_sinks_verified\":6,"
                    + "\"console_pending_parent_verification\":true,\"diagnostics_retained\":true,"
                    + "\"context_classloader_transition\":true,\"production_http_requests\":0}");
        } finally {
            release.countDown();
            if (worker != null) {
                worker.join(5000);
                if (worker.isAlive()) {
                    worker.interrupt();
                    worker.join(2000);
                }
            }
            Thread.currentThread().setContextClassLoader(originalLoader);
            manager.reset();
        }
        check(worker == null || !worker.isAlive(), "Native fixture worker remained active");
        check(workerFailure.get() == null, "Native request fixture failed");
    }
}
