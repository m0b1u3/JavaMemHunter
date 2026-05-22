package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EvidenceWriterTest {

    private Finding sampleFinding() {
        Finding f = new Finding();
        f.id = "F-001";
        f.type = "tomcat.filter";
        f.name = "EvilFilter";
        f.className = "com.evil.EvilFilter";
        f.score = 80;
        f.level = "HIGH";
        f.reasons.add("loaded from temp");
        f.codeSource = "/tmp/x.jar";
        f.classLoader = "WebAppClassLoader";
        f.recommendation = "remove";
        return f;
    }

    private CleanPlan samplePlan() {
        CleanPlan p = new CleanPlan();
        p.findingId = "F-001";
        p.type = "tomcat.filter";
        p.filterName = "EvilFilter";
        p.filterClass = "com.evil.EvilFilter";
        p.contextPath = "/app";
        p.level = "HIGH";
        p.urlPatterns = Arrays.asList("/*");
        p.steps = Arrays.asList("stop", "remove");
        p.score = 80;
        p.forced = false;
        p.rollbackSupported = true;
        p.generatedAt = 1234567L;
        return p;
    }

    @Test
    void writesFullBundle(@TempDir Path tmp) throws Exception {
        EvidenceWriter w = new EvidenceWriter(tmp);
        Finding f = sampleFinding();
        CleanPlan plan = samplePlan();
        Map<String, Object> snap = new HashMap<>();
        snap.put("filterName", "EvilFilter");
        snap.put("urlPatterns", Arrays.asList("/*"));
        byte[] bytecode = new byte[16];
        for (int i = 0; i < 16; i++) bytecode[i] = (byte) i;

        Path dir = w.writeBundle(f, plan, snap, bytecode);

        assertEquals(tmp.resolve("evidence").resolve("F-001"), dir);
        assertTrue(Files.exists(dir.resolve("finding.json")));
        assertTrue(Files.exists(dir.resolve("clean-plan.json")));
        assertTrue(Files.exists(dir.resolve("before-snapshot.json")));
        assertTrue(Files.exists(dir.resolve("bytecode.bin")));
        assertTrue(Files.exists(dir.resolve("bytecode.sha256")));

        assertArrayEquals(bytecode, Files.readAllBytes(dir.resolve("bytecode.bin")));

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytecode);
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) hex.append(String.format("%02x", b));
        String sha = new String(Files.readAllBytes(dir.resolve("bytecode.sha256")));
        assertEquals(hex.toString(), sha);
        assertFalse(sha.endsWith("\n"));
    }

    @Test
    void nullBytecodeSkipsBytecodeFiles(@TempDir Path tmp) throws Exception {
        EvidenceWriter w = new EvidenceWriter(tmp);
        Path dir = w.writeBundle(sampleFinding(), samplePlan(), new HashMap<>(), null);

        assertTrue(Files.exists(dir.resolve("finding.json")));
        assertTrue(Files.exists(dir.resolve("clean-plan.json")));
        assertTrue(Files.exists(dir.resolve("before-snapshot.json")));
        assertFalse(Files.exists(dir.resolve("bytecode.bin")));
        assertFalse(Files.exists(dir.resolve("bytecode.sha256")));
    }

    @Test
    void writeResultProducesParseableJson(@TempDir Path tmp) throws Exception {
        EvidenceWriter w = new EvidenceWriter(tmp);
        w.writeBundle(sampleFinding(), samplePlan(), new HashMap<>(), null);

        CleanResult r = new CleanResult();
        r.findingId = "F-001";
        r.success = true;
        r.rolledBack = false;
        r.verifiedDisappeared = true;
        r.executedSteps = Arrays.asList("stop", "remove");
        r.executedAt = 999L;

        w.writeResult("F-001", r);

        Path file = tmp.resolve("evidence").resolve("F-001").resolve("clean-result.json");
        assertTrue(Files.exists(file));

        CleanResult back = new ObjectMapper().readValue(file.toFile(), CleanResult.class);
        assertEquals("F-001", back.findingId);
        assertTrue(back.success);
        assertFalse(back.rolledBack);
        assertTrue(back.verifiedDisappeared);
        assertEquals(Arrays.asList("stop", "remove"), back.executedSteps);
        assertEquals(999L, back.executedAt);
    }
}
