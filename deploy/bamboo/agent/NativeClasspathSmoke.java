import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Runs only the real vendor cache predicate, never an Agent or HTTP request. */
public final class NativeClasspathSmoke {
    public static void main(String[] args) throws Exception {
        Path home = Path.of(args[0]);
        List<String> rows = Files.readAllLines(Path.of(args[1]));
        Class<?> entryClass = Class.forName("com.atlassian.bamboo.agent.bootstrap.AgentFileManifestDao$AgentFileManifestEntry");
        var constructor = entryClass.getConstructor(String.class, String.class, long.class, String.class);
        Method needsDownload = Class.forName("com.atlassian.bamboo.agent.bootstrap.ClasspathBuilder").getDeclaredMethod(
                "lambda$sync$3", File.class, entryClass);
        needsDownload.setAccessible(true);
        int accepted = 0;
        Object first = null;
        for (String row : rows) {
            String[] fields = row.split("\t");
            Object entry = constructor.newInstance(
                    "classpath", fields[0], Long.parseLong(fields[1]),
                    Long.toString(Long.parseUnsignedLong(fields[2], 16)));
            if ((boolean) needsDownload.invoke(null, home.toFile(), entry)) {
                throw new AssertionError("Vendor would download verified payload: " + fields[0]);
            }
            if (first == null) first = entry;
            accepted++;
        }
        if (first == null) throw new AssertionError("No vendor payload");
        Path sample = home.resolve(rows.get(0).split("\t")[0]);
        byte[] original = Files.readAllBytes(sample);
        try {
            Files.delete(sample);
            requireDownload(needsDownload, home, first, "missing");
            Files.write(sample, new byte[original.length + 1]);
            requireDownload(needsDownload, home, first, "length mismatch");
            byte[] changed = original.clone();
            changed[0] ^= 1;
            Files.write(sample, changed);
            requireDownload(needsDownload, home, first, "same-size checksum mismatch");
        } finally {
            Files.write(sample, original);
        }
        if ((boolean) needsDownload.invoke(null, home.toFile(), first)) {
            throw new AssertionError("Restored payload rejected");
        }
        System.out.println("NATIVE_CACHE_ACCEPTED=" + accepted + " INVALID_CACHE_REJECTED=3 RESTORED=1 HTTP_REQUESTS=0");
    }

    private static void requireDownload(Method method, Path home,
            Object entry, String reason) throws Exception {
        if (!(boolean) method.invoke(null, home.toFile(), entry)) {
            throw new AssertionError("Vendor accepted " + reason);
        }
    }
}
