package com.memhunter.agent.cleaner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * Persists the per-finding evidence bundle under {@code <baseDir>/evidence/<findingId>/}.
 *
 * <p>Layout (see v0.6 design doc §3.3):
 * <pre>
 *   finding.json
 *   clean-plan.json
 *   before-snapshot.json
 *   bytecode.bin          (optional)
 *   bytecode.sha256       (optional, paired with bytecode.bin)
 *   clean-result.json     (written later via writeResult)
 * </pre>
 */
public class EvidenceWriter {

    private final Path baseDir;
    private final ObjectMapper mapper;

    public EvidenceWriter(Path baseDir) {
        this.baseDir = baseDir;
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public Path writeBundle(Finding finding, CleanPlan plan,
                            Map<String, Object> beforeSnapshot, byte[] bytecode) throws IOException {
        Path dir = baseDir.resolve("evidence").resolve(finding.id);
        Files.createDirectories(dir);

        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("finding.json").toFile(), finding);
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-plan.json").toFile(), plan);
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("before-snapshot.json").toFile(), beforeSnapshot);

        if (bytecode != null) {
            Files.write(dir.resolve("bytecode.bin"), bytecode);
            Files.write(dir.resolve("bytecode.sha256"),
                    sha256Hex(bytecode).getBytes(StandardCharsets.US_ASCII));
        }
        return dir;
    }

    public void writeResult(String findingId, CleanResult result) throws IOException {
        Path dir = baseDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("clean-result.json").toFile(), result);
    }

    private static String sha256Hex(byte[] data) throws IOException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }
}
