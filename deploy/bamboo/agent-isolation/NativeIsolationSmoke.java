package com.mellivora.bamboo.isolation;

import java.io.InputStream;
import java.lang.reflect.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.beans.factory.config.InstantiationAwareBeanPostProcessor;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.ClassPathResource;
import org.apache.activemq.broker.BrokerService;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.command.ActiveMQQueue;
import jakarta.jms.Connection;
import jakarta.jms.Session;
import jakarta.jms.Message;
import jakarta.jms.MessageProducer;

/** Proof-only local transport. Never invokes RemoteAgent.main or the frozen bootstrap. */
public final class NativeIsolationSmoke {
    private static final String REMOTE = "com.atlassian.bamboo.v2.build.agent.remote.";
    private static final String UUID_VALUE = "01234567-89ab-4cde-8fab-0123456789ab";
    private static final String ORIGIN = "https://synthetic.invalid/bamboo/";
    private static final String ASSIGNMENT = "a".repeat(64);
    private static final List<String> CONSUMERS = List.of("agentMessageListenerConnector",
        "remoteEventRebroadcasterMessageListenerContainer", "executableBuildAgent", "heartBeatScheduler",
        "remoteEventRebroadcasterMessageListenerContainerLongLived");
    private static byte[] priorPermit;
    private static int checks;

    private static synchronized void require(boolean value, String code) {
        if (!value) throw new AssertionError(code);
        checks++;
    }
    private static void restore(String key,String value) {
        if (value == null) System.clearProperty(key); else System.setProperty(key,value);
    }
    private static Class<?> type(String name) throws Exception { return Class.forName(name); }
    private static void field(Object target, String name, Object value) throws Exception {
        Class<?> current = target instanceof Class<?> c ? c : target.getClass();
        while (current != null) {
            try {
                Field f = current.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target instanceof Class<?> ? null : target, value);
                return;
            } catch (NoSuchFieldException ignored) { current = current.getSuperclass(); }
        }
        throw new NoSuchFieldException(name);
    }
    private static Object invoke(Object target, String name, Class<?>[] parameters, Object... arguments) throws Exception {
        return target.getClass().getMethod(name, parameters).invoke(target, arguments);
    }
    private static Object proxy(String name, InvocationHandler handler) throws Exception {
        return Proxy.newProxyInstance(NativeIsolationSmoke.class.getClassLoader(), new Class<?>[]{type(name)}, (p,m,a) -> {
            if (m.getDeclaringClass() == Object.class) {
                return switch (m.getName()) { case "toString" -> "synthetic-local-boundary"; case "hashCode" -> System.identityHashCode(p); case "equals" -> p == a[0]; default -> null; };
            }
            return handler.invoke(p,m,a);
        });
    }
    private static Object zero(Class<?> result) {
        if (!result.isPrimitive() || result == void.class) return null;
        if (result == boolean.class) return false;
        if (result == long.class) return 0L;
        if (result == int.class) return 0;
        if (result == double.class) return 0d;
        if (result == float.class) return 0f;
        if (result == short.class) return (short)0;
        if (result == byte.class) return (byte)0;
        return (char)0;
    }
    private static Path directory(Path parent, String name) throws Exception {
        return Files.createDirectory(parent.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    private static void properties(Path path, Properties values) throws Exception {
        StringBuilder text = new StringBuilder();
        for (String key : new TreeSet<>(values.stringPropertyNames())) {
            text.append(key).append('=').append(values.getProperty(key).replace("\\", "\\\\")).append('\n');
        }
        Files.writeString(path, text, StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private static Properties read(Path path) throws Exception {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(path)) { p.load(in); }
        return p;
    }

    private static final class Fixture implements AutoCloseable {
        final Path root, requests, permit, profile, staleDisk;
        final AtomicInteger registrations = new AtomicInteger(), publications = new AtomicInteger();
        final AtomicInteger consumers = new AtomicInteger(), deliveries = new AtomicInteger();
        final GenericApplicationContext spring = new GenericApplicationContext();
        final DefaultListableBeanFactory beans = spring.getDefaultListableBeanFactory();
        final BrokerService broker = new BrokerService();
        final ActiveMQQueue queue = new ActiveMQQueue("synthetic-command");
        final Object configuration;
        final String priorHome = System.getProperty("bamboo.home");
        final String priorAgentHome = System.getProperty("bamboo.agent.home");
        final String priorProfile = System.getProperty("bamboo.isolation.profile");
        final long registeredId;

        Fixture(Path parent, Path proof, String name, long oldId, long newId, String uuid, String origin, long trustedUid) throws Exception {
            registeredId = newId;
            root = directory(parent, name);
            requests = directory(root, "requests");
            permit = root.resolve("permit.properties");
            profile = root.resolve("profile.properties");
            staleDisk = root.resolve("bamboo-agent.cfg.xml");
            Properties p = new Properties();
            p.setProperty("schema", "1"); p.setProperty("agent.id", "41");
            p.setProperty("agent.uuid", UUID_VALUE); p.setProperty("server.url", ORIGIN);
            p.setProperty("assignments.sha256", ASSIGNMENT); p.setProperty("wait.millis", "600");
            p.setProperty("request.directory", requests.toString()); p.setProperty("permit.path", permit.toString());
            properties(profile, p);
            Object xml = type("org.apache.commons.configuration.XMLConfiguration").getConstructor().newInstance();
            invoke(xml, "setProperty", new Class<?>[]{String.class,Object.class}, "agentDefinition.id", oldId);
            invoke(xml, "setProperty", new Class<?>[]{String.class,Object.class}, "agentDefinition.name", "synthetic");
            invoke(xml, "setProperty", new Class<?>[]{String.class,Object.class}, "agentDefinition.description", "synthetic");
            invoke(xml, "setProperty", new Class<?>[]{String.class,Object.class}, "agentUuid", uuid);
            invoke(xml, "setFileName", new Class<?>[]{String.class}, staleDisk.toString());
            invoke(xml, "save", new Class<?>[]{});
            // Actual saveAgentDefinition updates memory, then catches ConfigurationException on this directory sink.
            invoke(xml, "setFileName", new Class<?>[]{String.class}, root.toString());
            Class<?> home = type("com.atlassian.config.HomeLocator"), topic = type("jakarta.jms.Topic");
            configuration = type(REMOTE + "AgentConfiguration").getConstructor(home,topic,topic).newInstance(null,null,null);
            field(configuration,"xmlConfiguration",xml);
            field(configuration,"uuid",UUID.fromString(UUID_VALUE));
            beans.registerSingleton("agentConfiguration", configuration);
            System.setProperty("bamboo.home",root.toString());
            System.setProperty("bamboo.agent.home",root.toString());
            System.setProperty("bamboo.isolation.profile",profile.toString());
            Class<?> contextType = type("com.atlassian.bamboo.agent.bootstrap.AgentContext");
            Class<?> agentType = type("com.atlassian.bamboo.agent.AgentType");
            Object context = contextType.getConstructor(type("com.atlassian.bamboo.agent.bootstrap.http.RemoteAgentHttpClientFactory"),java.net.URL.class,String.class,agentType,String.class)
                .newInstance(null,new java.net.URL(origin),"unused-synthetic-fingerprint",agentType.getField("REMOTE").get(null),null);
            require(root.toFile().equals(type("com.atlassian.bamboo.agent.bootstrap.RemoteAgentHomeLocatorForBootstrap").getMethod("getHome").invoke(null)),"native-home-owned-fixture");
            field(context,"serverFingerprint","synthetic-fingerprint");
            field(context,"instanceFingerprint",1L);
            field(type(REMOTE + "RemoteAgent"),"context",context);
            Object agent = type(REMOTE + "RemoteAgent").getConstructor().newInstance();
            beans.registerSingleton("remoteAgent",agent);
            broker.setBrokerName("isolation-" + UUID.randomUUID());
            broker.setPersistent(false); broker.setUseJmx(false); broker.setUseShutdownHook(false); broker.setSchedulerSupport(false);
            broker.setDataDirectoryFile(root.resolve("broker").toFile());
            broker.start(); require(broker.waitUntilStarted(),"in-vm-broker-started");
            ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("vm://" + broker.getBrokerName() + "?create=false");
            beans.registerSingleton("connectionFactory",factory);
            beans.registerSingleton("agentCommandQueue",queue);
            Object converter = proxy("org.springframework.jms.support.converter.MessageConverter",(obj,method,args) -> {
                if (!method.getName().equals("fromMessage")) throw new AssertionError("unexpected-converter-operation");
                require(args[0] instanceof Message,"actual-jms-message-decoded");
                return proxy("com.atlassian.bamboo.v2.build.agent.messages.BambooAgentMessage",(payload,delivery,values) -> {
                    if (!delivery.getName().equals("deliver")) throw new AssertionError("unexpected-native-payload-method");
                    deliveries.incrementAndGet();
                    return null;
                });
            });
            beans.registerSingleton("jmsMessageConverterLazy",converter);
            try (Connection connection = factory.createConnection(); Session session = connection.createSession(false,Session.AUTO_ACKNOWLEDGE); MessageProducer producer = session.createProducer(queue)) {
                Message message = session.createTextMessage("synthetic-foreign-task-boundary");
                Class<?> selectors = type("com.atlassian.bamboo.v2.build.agent.messages.JmsSelectorUtils");
                message.setStringProperty("allowableAgents",(String)selectors.getMethod("getAgentsMessageProperty",Long.class).invoke(null,Long.valueOf(newId)));
                Object fingerprint = type(REMOTE + "RemoteAgent").getMethod("getFingerprint").invoke(null);
                type("com.atlassian.bamboo.amq.AgentJmsUtils").getMethod("setFingerprint",Message.class,type("com.atlassian.bamboo.setup.ServerFingerprint")).invoke(null,message,fingerprint);
                producer.send(message);
            }
            require(broker.getDestination(queue).getDestinationStatistics().getMessages().getCount() == 1,"synthetic-command-prequeued");
            beans.addBeanPostProcessor(new InstantiationAwareBeanPostProcessor() {
                @Override public Object postProcessBeforeInstantiation(Class<?> beanClass,String beanName) {
                    if (CONSUMERS.contains(beanName)) consumers.incrementAndGet();
                    if (CONSUMERS.contains(beanName) && root.getFileName().toString().startsWith("exit-")) {
                        try { Files.writeString(root.resolve("consumer.started"), beanName, StandardOpenOption.CREATE_NEW); }
                        catch (Exception e) { throw new IllegalStateException(e); }
                    }
                    return null;
                }
            });
            XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(spring);
            for (String filename : List.of("applicationContextRemoteAgentStartupCore.xml","applicationContextRemoteLongLivedAgentStartupCore.xml")) {
                if (trustedUid == 0) reader.loadBeanDefinitions(new ClassPathResource(filename));
                else reader.loadBeanDefinitions(new FileSystemResource(proof.resolve("graph").resolve(filename)));
            }
            if (name.startsWith("exit-")) beans.getBeanDefinition("isolationActivationGate").setInitMethodName("initialize");
            // Retain every native definition, class, constructor/inner listener, SpEL and dependency edge.
            // Only laziness changes: unrelated native services must not start during this bounded proof.
            for (String bean : beans.getBeanDefinitionNames()) beans.getBeanDefinition(bean).setLazyInit(true);
            RootBeanDefinition registration = new RootBeanDefinition(type(REMOTE + "AgentRegistrationBean"));
            registration.setLazyInit(true);
            registration.setInstanceSupplier(() -> {
                try { return registration(); } catch (Exception e) { throw new IllegalStateException(e); }
            });
            beans.registerBeanDefinition("agentRegistrationBean",registration);
            var lifecycle = new org.springframework.context.support.DefaultLifecycleProcessor() {
                @Override public void onRefresh() {
                    // Proof scope: defer SmartLifecycle auto-start (which otherwise ignores lazy-init).
                    // The command container alone is explicitly started after real gate completion.
                }
            };
            lifecycle.setBeanFactory(beans);
            beans.registerSingleton("lifecycleProcessor",lifecycle);
            spring.refresh();
        }
        void boundary(Object target,String name,Object value) throws Exception {
            beans.registerSingleton(name,value);
            field(target,name,value);
        }
        Object registration() throws Exception {
            Object registration = type(REMOTE + "AgentRegistrationBean").getConstructor().newInstance();
            field(registration,"agentConfiguration",configuration);
            for (String[] dependency : new String[][]{
                {"capabilityDefaultsHelper","com.atlassian.bamboo.v2.build.agent.capability.CapabilityDefaultsHelper"},
                {"defaultAgentCapabilityManager","com.atlassian.bamboo.v2.build.agent.capability.DefaultAgentCapabilityManager"}}) {
                boundary(registration,dependency[0],proxy(dependency[1],(p,m,a) -> a != null && a.length > 0 && m.getReturnType().isInstance(a[0]) ? a[0] : zero(m.getReturnType())));
            }
            boundary(registration,"eventPublisher",proxy("com.atlassian.event.api.EventPublisher",(p,m,a) -> { if (m.getName().equals("publish")) publications.incrementAndGet(); return zero(m.getReturnType()); }));
            boundary(registration,"remoteAgentManager",proxy("com.atlassian.bamboo.buildqueue.manager.RemotedRemoteAgentManager",(p,m,a) -> {
                if (!m.getName().equals("registerAgent")) return zero(m.getReturnType());
                registrations.incrementAndGet();
                if (root.getFileName().toString().startsWith("exit-")) Files.writeString(root.resolve("registration.observed"), Long.toString(registeredId), StandardOpenOption.CREATE_NEW);
                // Synthetic RPC reply only. This does NOT qualify stock server missing-record allocation.
                return type("com.atlassian.bamboo.v2.build.agent.RemotableRemoteAgentDefinitionImpl")
                    .getConstructor(long.class,String.class,String.class,UUID.class,type("com.atlassian.bamboo.ResultKey"))
                    .newInstance(registeredId,"synthetic","synthetic",UUID.fromString(UUID_VALUE),null);
            }));
            return registration;
        }
        void attest(String mutation, List<Future<?>> attempts) throws Exception {
            Path request = null;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (request == null && System.nanoTime() < deadline) {
                try (var paths = Files.list(requests)) { request = paths.filter(p -> p.getFileName().toString().endsWith(".properties")).findFirst().orElse(null); }
                if (request == null) {
                    for (Future<?> attempt : attempts) {
                        if (attempt.isDone()) {
                            attempt.get();
                            throw new AssertionError("consumer-completed-before-attestation");
                        }
                    }
                }
                if (request == null) Thread.sleep(5);
            }
            require(request != null,"fresh-challenge-created");
            Properties p = read(request);
            long now = System.currentTimeMillis();
            p.setProperty("server.enabled","true"); p.setProperty("server.exclusive","true");
            p.setProperty("issued.at.millis",Long.toString(now)); p.setProperty("expires.at.millis",Long.toString(now + 10000));
            if (mutation.equals("nonce")) p.setProperty("nonce",UUID.randomUUID().toString());
            if (mutation.equals("assignment")) p.setProperty("assignments.sha256","b".repeat(64));
            if (mutation.equals("expired")) { p.setProperty("issued.at.millis",Long.toString(now-10000)); p.setProperty("expires.at.millis",Long.toString(now-1)); }
            if (mutation.equals("uuid")) p.setProperty("agent.uuid",UUID.randomUUID().toString());
            if (mutation.equals("origin")) p.setProperty("server.url","https://other.invalid/");
            Path staged = root.resolve("permit.staged"); properties(staged,p);
            Files.move(staged,permit,StandardCopyOption.ATOMIC_MOVE);
        }
        @Override public void close() throws Exception {
            if (beans.containsSingleton("agentMessageListenerConnector")) {
                Object container = beans.getSingleton("agentMessageListenerConnector");
                invoke(container,"stop",new Class<?>[]{});
            }
            spring.close();
            broker.stop(); broker.waitUntilStopped();
            restore("bamboo.home",priorHome);
            restore("bamboo.agent.home",priorAgentHome);
            restore("bamboo.isolation.profile",priorProfile);
        }
    }

    private static void scenario(Path root, Path proof, String name, long oldId, long newId, String uuid, String origin, long uid, String permitMutation, boolean allowed) throws Exception {
        try (Fixture f = new Fixture(root,proof,name,oldId,newId,uuid,origin,uid)) {
            if ("replay".equals(permitMutation)) {
                require(priorPermit != null,"prior-permit-available");
                Files.write(f.permit,priorPermit,StandardOpenOption.CREATE_NEW);
                Files.setPosixFilePermissions(f.permit,PosixFilePermissions.fromString("rw-------"));
            }
            ExecutorService workers = Executors.newFixedThreadPool(CONSUMERS.size());
            try {
                List<Future<?>> attempts = new ArrayList<>();
                List<String> requested = allowed ? List.of("agentMessageListenerConnector") : CONSUMERS;
                for (String consumer : requested) attempts.add(workers.submit(() -> f.beans.getBean(consumer)));
                if (permitMutation != null && !permitMutation.equals("replay")) {
                    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                    while (f.registrations.get() == 0 && System.nanoTime() < until) Thread.sleep(5);
                    require(f.consumers.get() == 0 && f.deliveries.get() == 0,"no-consumer-before-permit");
                    require(f.broker.getDestination(f.queue).getDestinationStatistics().getDequeues().getCount() == 0,"actual-broker-no-dequeue-before-permit");
                    f.attest(permitMutation, attempts);
                }
                int success = 0;
                for (Future<?> attempt : attempts) {
                    try { attempt.get(5,TimeUnit.SECONDS); success++; }
                    catch (ExecutionException e) {
                        if (allowed) throw e;
                        boolean gateDenied = false;
                        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
                            if (cause.getMessage() != null && cause.getMessage().contains("ISOLATION_")) gateDenied = true;
                        }
                        require(gateDenied,"fixed-code-gate-denial-" + name);
                    }
                }
                require(allowed ? success == 1 : success == 0,"consumer-decision-" + name);
                require(f.registrations.get() == 1 && f.publications.get() == 1,"actual-registration-lifecycle-once");
                require((Long)invoke(f.configuration,"getAgentId",new Class<?>[]{}) == newId,"native-in-memory-id");
                Object disk = type("org.apache.commons.configuration.XMLConfiguration").getConstructor().newInstance();
                invoke(disk,"setFileName",new Class<?>[]{String.class},f.staleDisk.toString());
                invoke(disk,"load",new Class<?>[]{});
                require((Long)invoke(disk,"getLong",new Class<?>[]{String.class},"agentDefinition.id") == oldId,"stale-disk-retained");
                if (allowed) {
                    Object container = f.beans.getSingleton("agentMessageListenerConnector");
                    invoke(container,"start",new Class<?>[]{});
                    priorPermit = Files.readAllBytes(f.permit);
                    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                    while ((f.deliveries.get() == 0 || f.broker.getDestination(f.queue).getDestinationStatistics().getDequeues().getCount() == 0) && System.nanoTime() < until) Thread.sleep(5);
                    require(f.deliveries.get() == 1 && f.consumers.get() == 1,"native-listener-deliver-callback");
                    require(f.broker.getDestination(f.queue).getDestinationStatistics().getDequeues().getCount() == 1,"actual-broker-postpermit-dequeue");
                } else {
                    require(f.deliveries.get() == 0 && f.consumers.get() == 0,"zero-native-consumer-instantiation");
                    require(f.broker.getDestination(f.queue).getDestinationStatistics().getDequeues().getCount() == 0,"actual-broker-zero-negative-dequeue");
                }
                System.out.println("PASS " + name);
            } finally { workers.shutdownNow(); require(workers.awaitTermination(5,TimeUnit.SECONDS),"workers-terminated"); }
        }
    }
    private static void discovery(Path out, String name) throws Exception {
        Path proof = out.resolve("proof-not-installable");
        Path root = directory(proof, "discovery-" + name);
        long newId = name.equals("invalid-id") ? -1 : 73;
        String uuid = name.equals("new-uuid") ? UUID.randomUUID().toString() : UUID_VALUE;
        String origin = name.equals("wrong-origin") ? "https://other.invalid/" : ORIGIN;
        boolean published = !Set.of("invalid-id", "wrong-origin", "extra-profile", "missing-directory").contains(name);
        try (Fixture f = new Fixture(root, proof, name, -1, newId, uuid, origin, 1000)) {
            Properties activation = read(f.profile);
            Properties profile = new Properties();
            profile.setProperty("schema", "1");
            profile.setProperty("mode", "registration-only");
            profile.setProperty("server.url", ORIGIN);
            profile.setProperty("receipt.directory", Set.of("missing-directory", "exit-failure").contains(name) ? root.resolve("absent").toString() : f.requests.toString());
            if (name.equals("extra-profile")) profile.setProperty("agent.id", "41");
            Files.delete(f.profile);
            properties(f.profile, profile);
            if (name.startsWith("exit-")) {
                // A live non-daemon thread makes a runner-thread failure insufficient.
                new Thread(() -> { try { Thread.sleep(60000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }, "synthetic-live-thread").start();
                new Thread(() -> f.beans.getBean("agentMessageListenerConnector"), "synthetic-agent-runner").start();
                Thread.sleep(15000);
                throw new AssertionError("discovery-did-not-halt-jvm");
            }
            // A complete, fresh operator permit must have no route to discovery activation.
            Properties permit = new Properties();
            permit.setProperty("schema", "1"); permit.setProperty("nonce", UUID.randomUUID().toString());
            permit.setProperty("agent.id", Long.toString(newId)); permit.setProperty("agent.uuid", uuid);
            permit.setProperty("server.url", origin); permit.setProperty("assignments.sha256", ASSIGNMENT);
            permit.setProperty("server.enabled", "true"); permit.setProperty("server.exclusive", "true");
            long now = System.currentTimeMillis();
            permit.setProperty("issued.at.millis", Long.toString(now));
            permit.setProperty("expires.at.millis", Long.toString(now + 10000));
            properties(f.permit, permit);
            ExecutorService workers = Executors.newFixedThreadPool(CONSUMERS.size() + 1);
            AtomicBoolean finished = new AtomicBoolean();
            try {
                Future<?> reader = workers.submit(() -> {
                    while (!finished.get()) {
                        try (var files = Files.list(f.requests)) {
                            for (Path path : files.filter(p -> p.toString().endsWith(".properties")).toList()) {
                                Properties receipt = read(path);
                                if (!receipt.stringPropertyNames().equals(Set.of("schema", "mode", "nonce", "agent.id", "agent.uuid", "server.url"))) throw new AssertionError("atomic-complete-discovery-receipt");
                            }
                        } catch (Exception e) { throw new IllegalStateException(e); }
                        Thread.yield();
                    }
                });
                List<Future<?>> attempts = new ArrayList<>();
                for (String consumer : CONSUMERS) attempts.add(workers.submit(() -> f.beans.getBean(consumer)));
                for (Future<?> attempt : attempts) {
                    try { attempt.get(5, TimeUnit.SECONDS); throw new AssertionError("discovery-consumer-started"); }
                    catch (ExecutionException e) {
                        boolean denied = false;
                        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
                            if (cause.getMessage() != null && cause.getMessage().contains("ISOLATION_")) denied = true;
                        }
                        require(denied, "discovery-fixed-denial");
                    }
                }
                finished.set(true); reader.get(5, TimeUnit.SECONDS);
                require(f.registrations.get() == 1 && f.publications.get() == 1, "discovery-native-registration-once");
                require(f.consumers.get() == 0 && f.deliveries.get() == 0, "discovery-no-native-consumers");
                require(f.broker.getDestination(f.queue).getDestinationStatistics().getDequeues().getCount() == 0, "discovery-no-broker-dequeue");
                List<Path> receipts;
                try (var files = Files.list(f.requests)) { receipts = files.toList(); }
                require(receipts.size() == (published ? 1 : 0), "discovery-exactly-one-complete-publication-or-none");
                if (published) {
                    Properties receipt = read(receipts.get(0));
                    require("1".equals(receipt.getProperty("schema")) && "registration-only".equals(receipt.getProperty("mode")), "discovery-not-an-activation-challenge");
                    require(Long.toString(newId).equals(receipt.getProperty("agent.id")), "discovery-actual-postregistration-id-not-stale-disk");
                    require(uuid.equals(receipt.getProperty("agent.uuid")) && origin.equals(receipt.getProperty("server.url")), "discovery-actual-uuid-and-server");
                    require(receipts.get(0).getFileName().toString().equals(UUID.fromString(receipt.getProperty("nonce")) + ".properties"), "discovery-committed-filename");
                    require(Files.getPosixFilePermissions(receipts.get(0)).equals(PosixFilePermissions.fromString("rw-------")), "discovery-private-receipt");
                }
                // Failed Spring bean creation is retryable. A replacement bound profile and
                // fresh permit cannot turn this same process into an activation process.
                Files.delete(f.profile); properties(f.profile, activation);
                boolean locked = false;
                try { new ActivationGate(f.profile.toString(), 41, UUID_VALUE, ORIGIN, 1000).awaitActivation(); }
                catch (IllegalStateException e) { locked = e.getMessage().contains("LOCKED"); }
                require(locked, "discovery-process-mode-irreversible-even-after-publication-failure");
                try (var files = Files.list(f.requests)) { require(files.count() == receipts.size(), "discovery-never-issued-activation-challenge"); }
                System.out.println("PASS discovery-" + name);
                System.out.println("PASS checks=" + checks);
            } finally {
                finished.set(true); workers.shutdownNow();
                require(workers.awaitTermination(5, TimeUnit.SECONDS), "discovery-workers-terminated");
            }
        }
    }

    private static void discoveryChildren(Path out, Path nativeDir) throws Exception {
        for (String name : List.of("fresh-id", "new-uuid", "invalid-id", "wrong-origin", "extra-profile", "missing-directory")) {
            Path captured = out.resolve("proof-not-installable").resolve("discovery-" + name + ".output");
            ProcessBuilder builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-javaagent:" + out.resolve("bamboo-isolation-candidate.jar"), "-cp", System.getProperty("java.class.path"),
                NativeIsolationSmoke.class.getName(), out.toString(), nativeDir.toString(), name);
            for (String key : new ArrayList<>(builder.environment().keySet())) {
                if (Set.of("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "JAVA_OPTS", "JDK_JAVAC_OPTIONS").contains(key.toUpperCase(Locale.ROOT))) builder.environment().remove(key);
            }
            builder.redirectErrorStream(true).redirectOutput(captured.toFile());
            Process process = builder.start();
            if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("discovery-child-timeout"); }
            require(process.exitValue() == 0, "discovery-child-exit-" + name);
            String output = Files.readString(captured);
            require(output.contains("PASS discovery-" + name), "discovery-child-proof-" + name);
            System.out.println("PASS discovery-" + name);
        }
        for (String name : List.of("exit-success", "exit-failure")) {
            Path captured = out.resolve("proof-not-installable").resolve("discovery-" + name + ".output");
            ProcessBuilder builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-javaagent:" + out.resolve("bamboo-isolation-candidate.jar"), "-cp", System.getProperty("java.class.path"),
                NativeIsolationSmoke.class.getName(), out.toString(), nativeDir.toString(), name);
            for (String key : new ArrayList<>(builder.environment().keySet())) {
                if (Set.of("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "JAVA_OPTS", "JDK_JAVAC_OPTIONS").contains(key.toUpperCase(Locale.ROOT))) builder.environment().remove(key);
            }
            builder.redirectErrorStream(true).redirectOutput(captured.toFile());
            Process process = builder.start();
            if (!process.waitFor(20, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("discovery-exit-timeout"); }
            require(process.exitValue() == 78, "discovery-production-process-halt-" + name);
            Path fixture = out.resolve("proof-not-installable").resolve("discovery-" + name).resolve(name);
            require("73".equals(Files.readString(fixture.resolve("registration.observed"))), "discovery-production-postregistration-halt");
            require(!Files.exists(fixture.resolve("consumer.started")), "discovery-production-halt-before-consumer");
            try (var files = Files.list(fixture.resolve("requests"))) {
                List<Path> receipts = files.toList();
                require(receipts.size() == (name.equals("exit-success") ? 1 : 0), "discovery-production-publication-before-halt-or-none");
                if (!receipts.isEmpty()) require("73".equals(read(receipts.get(0)).getProperty("agent.id")), "discovery-production-complete-receipt");
            }
            System.out.println("PASS discovery-" + name);
        }
    }
    private static void child(String[] args) throws Exception {
        if (args[0].equals("resource-check")) {
            GuardedBootstrap.verifyResources();
        } else {
            Class.forName(REMOTE + "AgentRegistrationBean",false,NativeIsolationSmoke.class.getClassLoader());
        }
        System.out.println("PROOF_DELEGATE_REACHED");
    }
    private static void subprocess(Path out, Path nativeDir, String variant, String mode, int expected) throws Exception {
        Path proof = out.resolve("proof-not-installable");
        Path candidate = variant.equals("wrong-native") ? out.resolve("bamboo-isolation-candidate.jar") : proof.resolve(variant + ".jar");
        StringBuilder cp = new StringBuilder(proof.toString()).append(java.io.File.pathSeparator);
        if (variant.equals("wrong-native")) cp.append(proof.resolve("wrong-native.jar")).append(java.io.File.pathSeparator);
        cp.append(candidate);
        try (var paths = Files.list(nativeDir)) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".jar")).sorted().toList()) cp.append(java.io.File.pathSeparator).append(path);
        }
        ProcessBuilder builder = new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),
            "-javaagent:" + candidate,"-cp",cp.toString(),NativeIsolationSmoke.class.getName(),mode);
        for (String key : new ArrayList<>(builder.environment().keySet())) {
            if (Set.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","JAVA_OPTS","JDK_JAVAC_OPTIONS").contains(key.toUpperCase(Locale.ROOT))) builder.environment().remove(key);
        }
        Path captured = proof.resolve(variant + ".output");
        builder.redirectErrorStream(true).redirectOutput(captured.toFile());
        Process process = builder.start();
        if (!process.waitFor(15,TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("child-timeout"); }
        require(expected == 78 ? process.exitValue() == 78 : process.exitValue() != 0,"fail-before-delegate-" + variant);
        require(!Files.readString(captured).contains("PROOF_DELEGATE_REACHED"),"no-delegate-" + variant);
        System.out.println("PASS " + variant);
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 1) { child(args); return; }
        try {
            if (args.length == 3) discovery(Path.of(args[0]).toAbsolutePath(), args[2]);
            else runSuite(args);
        } finally {
            for (BrokerService owned : new ArrayList<>(org.apache.activemq.broker.BrokerRegistry.getInstance().getBrokers().values())) {
                if (owned.getBrokerName().startsWith("isolation-")) {
                    owned.stop();
                    owned.waitUntilStopped();
                }
            }
        }
    }

    private static void runSuite(String[] args) throws Exception {
        require(IsolationRuntimeGuard.isArmed(),"premain-armed");
        GuardedBootstrap.verifyResources();
        Path out = Path.of(args[0]).toAbsolutePath(), nativeDir = Path.of(args[1]).toAbsolutePath();
        Path proof = out.resolve("proof-not-installable");
        Path root = directory(proof,"runtime-" + UUID.randomUUID());
        require(((Number)Files.getAttribute(root,"unix:uid")).longValue() == 1000L,"qualification-requires-nonroot-uid1000");
        scenario(root,proof,"fresh-permit-racing-consumers",41,41,UUID_VALUE,ORIGIN,1000,"valid",true);
        scenario(root,proof,"prior-process-permit-replay",41,41,UUID_VALUE,ORIGIN,1000,"replay",false);
        scenario(root,proof,"missing-permit-timeout",41,41,UUID_VALUE,ORIGIN,1000,null,false);
        scenario(root,proof,"reassigned-stale-disk",41,42,UUID_VALUE,ORIGIN,1000,"replay",false);
        scenario(root,proof,"missing-id-stale-disk",41,-1,UUID_VALUE,ORIGIN,1000,"replay",false);
        scenario(root,proof,"uuid-profile-mismatch",41,41,UUID.randomUUID().toString(),ORIGIN,1000,null,false);
        scenario(root,proof,"origin-profile-mismatch",41,41,UUID_VALUE,"https://different.invalid/",1000,null,false);
        scenario(root,proof,"immutable-root-owner-negative",41,41,UUID_VALUE,ORIGIN,0,null,false);
        for (String invalid : List.of("nonce","assignment","expired","uuid","origin")) {
            scenario(root,proof,"permit-" + invalid,41,41,UUID_VALUE,ORIGIN,1000,invalid,false);
        }
        subprocess(out,nativeDir,"missing-xml","resource-check",1);
        subprocess(out,nativeDir,"changed-xml","resource-check",1);
        subprocess(out,nativeDir,"wrong-native","native-check",78);
        discoveryChildren(out, nativeDir);
        System.out.println("PASS checks=" + checks);
        System.out.println("LIMIT full stock RemoteAgent startup and stock server registration/allocation NOT exercised. All five actual native definitions retained; negatives request all five, positive executes command container plus XML inner BambooAgentMessageListener through in-VM ActiveMQ and a synthetic converter/payload deliver callback. Other four native services remain lazy, not replaced. No real bootstrap invoked.");
    }
}
