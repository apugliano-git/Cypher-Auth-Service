package com.augustopugliano.cypher;

import java.nio.file.*;
import java.security.*;
import java.util.UUID;
import org.springframework.core.io.FileSystemResource;

public final class TestKeys {
    public static final String PASSWORD = UUID.randomUUID().toString();
    public static final Path PATH = create();
    public static final PrivateKey PRIVATE = privateKey();
    public static FileSystemResource resource() { return new FileSystemResource(PATH); }
    private static Path create() {
        try {
            Path path = Files.createTempDirectory("cypher-key-").resolve("test.p12");
            Process p = new ProcessBuilder("keytool", "-genkeypair", "-alias", "cypher-key", "-keyalg", "RSA", "-keysize", "2048", "-storetype", "PKCS12", "-keystore", path.toString(), "-storepass", PASSWORD, "-dname", "CN=Synthetic Cypher Test", "-validity", "1", "-noprompt").redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if (!p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS) || p.exitValue() != 0) throw new IllegalStateException("keytool failed");
            path.getParent().toFile().deleteOnExit();
            path.toFile().deleteOnExit();
            return path;
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static PrivateKey privateKey() {
        try (var in = Files.newInputStream(PATH)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, PASSWORD.toCharArray());
            return (PrivateKey) ks.getKey("cypher-key", PASSWORD.toCharArray());
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
}
