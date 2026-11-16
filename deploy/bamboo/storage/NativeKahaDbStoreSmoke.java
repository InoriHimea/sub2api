import jakarta.jms.Connection;
import jakarta.jms.DeliveryMode;
import jakarta.jms.Message;
import jakarta.jms.MessageConsumer;
import jakarta.jms.MessageProducer;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.broker.BrokerService;
import org.apache.activemq.store.kahadb.KahaDBPersistenceAdapter;

import java.nio.channels.SeekableByteChannel;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** Synthetic-only, cross-JVM KahaDB reopen qualification. Never points at Bamboo's JMS store. */
public final class NativeKahaDbStoreSmoke {
    private static final Path SHARED = Path.of("/data/atlassian/application-data/bamboo/shared");
    private static final String PREFIX = "omp-bamboo-jms-qualification-";
    private static final int COUNT = 4;
    private static final long RECEIVE_MS = 5000;
    private static final long EXTRA_MS = 1000;

    private NativeKahaDbStoreSmoke() { }

    public static void main(String[] args) {
        // Also bounds store-lock/start/stop failures, which JMS receive timeouts alone cannot bound.
        var watchdog = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "synthetic-store-deadline");
            thread.setDaemon(true);
            return thread;
        });
        watchdog.schedule(() -> {
            System.err.println("{\"ok\":false,\"code\":\"DEADLINE\"}");
            Runtime.getRuntime().halt(3);
        }, 60, TimeUnit.SECONDS);
        try {
            require(args.length == 3, "USAGE");
            String mode = args[0];
            require(mode.equals("write") || mode.equals("read"), "USAGE");
            String marker = args[2];
            require(UUID.fromString(marker).toString().equals(marker), "UUID");
            Path root = validateRoot(args[1], marker);
            Path store = root.resolve("store");
            Path runtime = root.resolve("runtime");
            Path complete = root.resolve("WRITE_COMPLETE");
            if (mode.equals("write")) {
                require(!Files.exists(store, LinkOption.NOFOLLOW_LINKS)
                        && !Files.exists(runtime, LinkOption.NOFOLLOW_LINKS)
                        && !Files.exists(complete, LinkOption.NOFOLLOW_LINKS), "WRITE_NOT_FRESH");
                Files.createDirectory(store);
                Files.createDirectory(runtime);
            } else {
                require(Files.isDirectory(store, LinkOption.NOFOLLOW_LINKS)
                        && Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS)
                        && Files.isRegularFile(store.resolve("db.data"), LinkOption.NOFOLLOW_LINKS),
                        "STORE_MISSING");
                requireMarker(complete, marker, "WRITE_INCOMPLETE");
            }
            runBroker(mode, root, store, runtime, marker);
            if (mode.equals("write")) {
                // Published only after JMS resources and the real persistent broker have closed.
                Files.writeString(complete, marker, StandardCharsets.US_ASCII,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            }
            System.out.println("{\"ok\":true,\"code\":\""
                    + (mode.equals("write") ? "WRITE_CLOSED" : "REOPEN_VERIFIED")
                    + "\",\"count\":" + COUNT + ",\"read_preserves_messages\":true}");
            watchdog.shutdownNow();
            System.exit(0);
        } catch (Exception failure) {
            String code = failure instanceof QualificationFailure
                    ? failure.getMessage() : "NATIVE_OR_FILESYSTEM_FAILURE";
            // Deliberately omit exception text, paths, broker internals and all message bodies.
            System.err.println("{\"ok\":false,\"code\":\"" + code + "\"}");
            System.exit(2);
        }
    }

    private static Path validateRoot(String value, String marker) throws Exception {
        Path root = Path.of(value);
        require(root.isAbsolute() && root.equals(root.normalize()) && root.getParent() != null
                && root.getParent().equals(SHARED)
                && root.getFileName().toString().startsWith(PREFIX)
                && root.getFileName().toString().length() > PREFIX.length(), "ROOT_SCOPE");
        // Check every ancestor too: an indirect link must not redirect qualification to a live path.
        for (Path part = root; part != null; part = part.getParent()) {
            require(!Files.isSymbolicLink(part), "SYMLINK");
        }
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS), "ROOT_MISSING");
        require(root.toRealPath().equals(root), "ROOT_SCOPE");
        requireMarker(root.resolve("OWNED_QUALIFICATION"), marker, "OWNERSHIP");
        try (Stream<Path> paths = Files.walk(root)) {
            require(paths.noneMatch(Files::isSymbolicLink), "SYMLINK");
        }
        return root;
    }

    private static void requireMarker(Path file, String marker, String code) throws Exception {
        require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) == 36, code);
        ByteBuffer bytes = ByteBuffer.allocate(37);
        try (SeekableByteChannel channel = Files.newByteChannel(file,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            while (bytes.hasRemaining() && channel.read(bytes) != -1) { }
        }
        bytes.flip();
        require(StandardCharsets.US_ASCII.decode(bytes).toString().equals(marker), code);
    }

    private static void runBroker(String mode, Path root, Path store, Path runtime, String marker)
            throws Exception {
        String name = "omp-jms-qualification-" + marker;
        KahaDBPersistenceAdapter persistence = new KahaDBPersistenceAdapter();
        persistence.setDirectory(store.toFile());
        persistence.setIndexDirectory(store.toFile());
        // Installed Bamboo defaults; do not load its live cluster-election locker in this fixture.
        persistence.setPreallocationStrategy("zeros");
        persistence.setJournalDiskSyncStrategy("always");
        persistence.setLockKeepAlivePeriod(20000);
        persistence.setUseLock(true);
        persistence.getLocker().setFailIfLocked(true);

        BrokerService broker = new BrokerService();
        broker.setBrokerName(name);
        broker.setPersistent(true);
        broker.setUseJmx(false);
        broker.setUseShutdownHook(false);
        broker.setAdvisorySupport(false);
        broker.setSchedulerSupport(false);
        broker.setDeleteAllMessagesOnStartup(false);
        broker.setDataDirectoryFile(runtime.toFile());
        broker.setTmpDataDirectory(runtime.resolve("tmp").toFile());
        broker.setPersistenceAdapter(persistence);
        require(broker.getTransportConnectors().isEmpty()
                && broker.getNetworkConnectors().isEmpty(), "CONNECTOR_CONFIG");
        try {
            // No addConnector: the client can attach only to this already-existing in-process broker.
            broker.start();
            require(broker.waitUntilStarted(10000), "BROKER_START");
            ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory(
                    "vm://" + name + "?create=false&waitForStart=5000");
            factory.setWatchTopicAdvisories(false);
            factory.setAlwaysSyncSend(true);
            factory.setSendTimeout(5000);
            factory.setCloseTimeout(5000);
            try (Connection connection = factory.createConnection();
                 Session session = connection.createSession(true, Session.SESSION_TRANSACTED)) {
                connection.start();
                var queue = session.createQueue("qualification." + marker);
                if (mode.equals("write")) {
                    try (MessageProducer producer = session.createProducer(queue)) {
                        for (int i = 0; i < COUNT; i++) {
                            TextMessage message = session.createTextMessage(body(marker, i));
                            message.setJMSCorrelationID(id(marker, i));
                            message.setIntProperty("syntheticSequence", i);
                            producer.send(message, DeliveryMode.PERSISTENT, 4, 0);
                        }
                    }
                    session.commit();
                } else {
                    Set<String> nativeIds = new HashSet<>();
                    try (MessageConsumer consumer = session.createConsumer(queue)) {
                        for (int i = 0; i < COUNT; i++) {
                            Message message = consumer.receive(RECEIVE_MS);
                            require(message instanceof TextMessage, "MESSAGE_TYPE_OR_COUNT");
                            require(body(marker, i).equals(((TextMessage) message).getText())
                                    && id(marker, i).equals(message.getJMSCorrelationID())
                                    && message.propertyExists("syntheticSequence")
                                    && message.getIntProperty("syntheticSequence") == i
                                    && message.getJMSDeliveryMode() == DeliveryMode.PERSISTENT
                                    && message.getJMSMessageID() != null
                                    && nativeIds.add(message.getJMSMessageID()), "MESSAGE_CONTENT_OR_ORDER");
                        }
                        require(consumer.receive(EXTRA_MS) == null, "EXTRA_MESSAGE");
                    }
                    // Preserve this synthetic corpus for independent subsequent host/JVM opens.
                    session.rollback();
                }
            }
            // Validate again before accepting the run; callers must keep the namespace exclusive.
            validateRoot(root.toString(), marker);
        } finally {
            broker.stop();
            broker.waitUntilStopped();
        }
    }

    private static String id(String marker, int sequence) {
        return "qualification:" + marker + ":" + sequence;
    }

    private static String body(String marker, int sequence) {
        return "SYNTHETIC_KAHADB_QUALIFICATION|" + marker + "|" + sequence;
    }

    private static void require(boolean condition, String code) throws QualificationFailure {
        if (!condition) {
            throw new QualificationFailure(code);
        }
    }

    private static final class QualificationFailure extends Exception {
        QualificationFailure(String code) {
            super(code);
        }
    }
}
