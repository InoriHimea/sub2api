package com.mellivora.bamboo.logging;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Handler;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.juli.OneLineFormatter;

/** Validates the fixed JULI profile before the application main is entered. */
public final class QuerySafeLoggingGuard {
    private static final String MANAGER = "org.apache.juli.ClassLoaderLogManager";
    private static final String FORMATTER = "com.mellivora.bamboo.logging.QuerySafeOneLineFormatter";
    private static final String PROBE = "com.mellivora.bamboo.logging.startupGuard";
    private static final String JULI_SHA256 =
            "83df7c64837fd51075f381b1ffbb5ecc442f8d6bc9b7db39faf2e5f6fb058c0c";

    private QuerySafeLoggingGuard() {
    }

    public static void premain(String options) {
        validate(options != null && !options.isEmpty());
    }

    /** Standalone validation uses only the JVM's already-specified logging configuration. */
    public static void main(String[] args) {
        validate(args == null || args.length != 0);
    }

    private static void validate(boolean hasOptions) {
        try {
            require(!hasOptions, "JUL_GUARD_OPTIONS");
            String configFile = System.getProperty("java.util.logging.config.file");
            require(MANAGER.equals(System.getProperty("java.util.logging.manager")),
                    "JUL_GUARD_MANAGER_PROPERTY");
            require(System.getProperty("java.util.logging.config.class") == null,
                    "JUL_GUARD_CONFIG_CLASS");
            require(configFile != null && !configFile.isEmpty(), "JUL_GUARD_CONFIG_FILE");
            Path configPath = Path.of(configFile);
            require(configPath.isAbsolute() && Files.isRegularFile(configPath),
                    "JUL_GUARD_CONFIG_FILE");
            Properties properties = new Properties();
            try (InputStream input = Files.newInputStream(configPath)) {
                // JULI reads logging.properties with Properties.load(InputStream), not a Reader.
                properties.load(input);
            }
            Map<String, String> declarations = declarations(properties);
            Map<String, List<String>> routes = routes(properties, declarations);
            require("false".equals(properties.getProperty(PROBE + ".useParentHandlers")),
                    "JUL_GUARD_PROBE_PARENT_PROPERTY");
            List<String> probeRoute = routes.get(PROBE + ".handlers");
            require(probeRoute != null && probeRoute.size() == declarations.size()
                            && probeRoute.containsAll(declarations.keySet()),
                    "JUL_GUARD_PROBE_ROUTE");
            verifyJuliSource();

            LogManager manager = LogManager.getLogManager();
            require(manager.getClass().getName().equals(MANAGER), "JUL_GUARD_MANAGER_INSTANCE");
            require(MANAGER.equals(System.getProperty("java.util.logging.manager"))
                            && System.getProperty("java.util.logging.config.class") == null
                            && configFile.equals(System.getProperty("java.util.logging.config.file")),
                    "JUL_GUARD_SYSTEM_PROPERTY_DRIFT");
            agree(manager, properties, "handlers");
            for (String declaration : declarations.keySet()) {
                agree(manager, properties, declaration + ".formatter");
            }
            for (String route : routes.keySet()) {
                // JULI exposes .handlers only while adding its local root logger.
                // Its effective root route is checked below through Logger.getHandlers().
                if (!route.equals(".handlers")) {
                    agree(manager, properties, route);
                }
            }
            agree(manager, properties, PROBE + ".useParentHandlers");

            // Accessing the real root and probe forces native lazy handler initialization.
            Logger root = manager.getLogger("");
            require(root != null, "JUL_GUARD_ROOT");
            root.getHandlers();
            Logger probe = Logger.getLogger(PROBE);
            require(!probe.getUseParentHandlers(), "JUL_GUARD_PROBE_PARENT_INSTANCE");
            Handler[] probeHandlers = probe.getHandlers();
            require(probeHandlers.length == probeRoute.size(), "JUL_GUARD_PROBE_HANDLER_COUNT");
            Map<String, Handler> declaredInstances = new LinkedHashMap<>();
            IdentityHashMap<Handler, Boolean> identities = new IdentityHashMap<>();
            for (int i = 0; i < probeHandlers.length; i++) {
                Handler handler = probeHandlers[i];
                String declaration = probeRoute.get(i);
                require(handler.getClass().getName().equals(declarations.get(declaration)),
                        "JUL_GUARD_PROBE_HANDLER_TYPE");
                require(identities.put(handler, Boolean.TRUE) == null,
                        "JUL_GUARD_PROBE_HANDLER_IDENTITY");
                verifyFormatter(handler);
                declaredInstances.put(declaration, handler);
            }

            // Hold strong references while checking the public logger inventory.
            List<Logger> loggers = new ArrayList<>();
            loggers.add(root);
            loggers.add(probe);
            Enumeration<String> names = manager.getLoggerNames();
            while (names.hasMoreElements()) {
                Logger logger = manager.getLogger(names.nextElement());
                if (logger != null) {
                    loggers.add(logger);
                }
            }
            for (Logger logger : loggers) {
                Handler[] handlers = logger.getHandlers();
                for (Handler handler : handlers) {
                    require(identities.containsKey(handler), "JUL_GUARD_UNDECLARED_HANDLER");
                    verifyFormatter(handler);
                }
                List<String> route = routes.get(logger.getName() + ".handlers");
                if (route == null && logger == root) {
                    route = new ArrayList<>(declarations.keySet());
                }
                verifyRoute(handlers, route == null ? List.of() : route, declaredInstances);
            }
        } catch (GuardFailure failure) {
            reject(failure.getMessage());
        } catch (Exception | LinkageError failure) {
            reject("JUL_GUARD_VALIDATION_FAILURE");
        }
    }

    private static void reject(String diagnostic) {
        // Diagnostics are fixed policy codes, never native exception messages or properties.
        System.err.println(diagnostic);
        System.exit(78);
        throw new IllegalStateException("JUL_GUARD_EXIT_RETURNED");
    }

    private static Map<String, String> declarations(Properties properties) {
        List<String> names = handlerNames(properties.getProperty("handlers"));
        require(!names.isEmpty(), "JUL_GUARD_HANDLER_DECLARATIONS");
        Map<String, String> declarations = new LinkedHashMap<>();
        for (String name : names) {
            String type = name;
            if (Character.isDigit(name.charAt(0))) {
                int separator = name.indexOf('.');
                require(separator > 0, "JUL_GUARD_HANDLER_TYPE");
                type = name.substring(separator + 1);
            }
            require(type.equals("org.apache.juli.AsyncFileHandler")
                            || type.equals("org.apache.juli.FileHandler")
                            || type.equals("java.util.logging.ConsoleHandler"),
                    "JUL_GUARD_HANDLER_TYPE");
            require(declarations.put(name, type) == null, "JUL_GUARD_DUPLICATE_DECLARATION");
            require(FORMATTER.equals(properties.getProperty(name + ".formatter")),
                    "JUL_GUARD_FORMATTER_PROPERTY");
        }
        return declarations;
    }

    private static Map<String, List<String>> routes(
            Properties properties, Map<String, String> declarations) {
        Map<String, List<String>> routes = new LinkedHashMap<>();
        for (String key : properties.stringPropertyNames()) {
            if (key.endsWith(".handlers")) {
                List<String> names = handlerNames(properties.getProperty(key));
                for (String name : names) {
                    require(declarations.containsKey(name), "JUL_GUARD_UNDECLARED_ROUTE");
                }
                routes.put(key, names);
            }
        }
        return routes;
    }

    private static List<String> handlerNames(String value) {
        if (value == null || value.trim().isEmpty()) {
            return List.of();
        }
        List<String> names = new ArrayList<>();
        for (String part : value.split(",", -1)) {
            String name = part.trim();
            require(!name.isEmpty(), "JUL_GUARD_EMPTY_HANDLER_NAME");
            names.add(name);
        }
        return names;
    }

    private static void agree(LogManager manager, Properties properties, String key) {
        require(properties.getProperty(key).equals(manager.getProperty(key)),
                "JUL_GUARD_RUNTIME_PROPERTY_DRIFT");
    }

    private static void verifyFormatter(Handler handler) {
        require(handler.getFormatter() != null
                        && handler.getFormatter().getClass() == QuerySafeOneLineFormatter.class,
                "JUL_GUARD_FORMATTER_INSTANCE");
    }

    private static void verifyRoute(Handler[] handlers, List<String> route,
            Map<String, Handler> declaredInstances) {
        require(handlers.length == route.size(), "JUL_GUARD_RUNTIME_ROUTE");
        IdentityHashMap<Handler, Integer> remaining = new IdentityHashMap<>();
        for (String declaration : route) {
            Handler handler = declaredInstances.get(declaration);
            remaining.put(handler, remaining.getOrDefault(handler, 0) + 1);
        }
        for (Handler handler : handlers) {
            int count = remaining.getOrDefault(handler, 0);
            require(count > 0, "JUL_GUARD_RUNTIME_ROUTE");
            remaining.put(handler, count - 1);
        }
    }

    private static void verifyJuliSource() throws Exception {
        CodeSource source = OneLineFormatter.class.getProtectionDomain().getCodeSource();
        require(source != null && source.getLocation() != null, "JUL_GUARD_JULI_SOURCE");
        URI location = source.getLocation().toURI();
        require("file".equals(location.getScheme()), "JUL_GUARD_JULI_SOURCE");
        Path jar = Path.of(location);
        require(jar.isAbsolute() && Files.isRegularFile(jar), "JUL_GUARD_JULI_SOURCE");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(jar)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
        }
        require(JULI_SHA256.equals(HexFormat.of().formatHex(digest.digest())),
                "JUL_GUARD_JULI_DIGEST");
    }

    private static void require(boolean condition, String diagnostic) {
        if (!condition) {
            throw new GuardFailure(diagnostic);
        }
    }

    private static final class GuardFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        GuardFailure(String diagnostic) {
            super(diagnostic, null, false, false);
        }
    }
}
