package com.memhunter.attach;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.verify.VerifyExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class AttachMainTest {

    @TempDir
    Path tempDir;

    @Test
    void clean_confirm_rejects_without_exact_yes_and_does_not_attach() throws Exception {
        String id = "F-123";
        writeCleanPlan(id);
        RecordingExecutor executor = new RecordingExecutor();

        int code = run(new String[]{
                "123", "agent.jar", "clean", "--id", id, "--confirm", "--evidence-dir", tempDir.toString()
        }, "no\n", executor);

        assertEquals(1, code);
        assertFalse(executor.called);
    }

    @Test
    void clean_confirm_loads_agent_after_exact_yes_and_prints_result() throws Exception {
        String id = "F-123";
        writeCleanPlan(id);
        CleanResult result = new CleanResult();
        result.findingId = id;
        result.success = true;
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("clean-result.json"), result);
        RecordingExecutor executor = new RecordingExecutor();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = AttachMain.run(new String[]{
                "123", "agent.jar", "clean", "--id", id, "--confirm", "--evidence-dir", tempDir.toString()
        }, input("yes\n"), new PrintStream(out), new PrintStream(new ByteArrayOutputStream()), executor);

        assertEquals(0, code);
        assertTrue(executor.called);
        assertEquals("123", executor.pid);
        assertEquals("agent.jar", executor.agentJar);
        assertTrue(executor.agentArgs.contains("clean --id F-123 --confirm"));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("success=true"));
    }

    @Test
    void clean_confirm_returns_nonzero_when_clean_result_failed() throws Exception {
        String id = "F-123";
        writeCleanPlan(id);
        CleanResult result = new CleanResult();
        result.findingId = id;
        result.success = false;
        result.failureReason = "verify failed";
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("clean-result.json"), result);
        RecordingExecutor executor = new RecordingExecutor();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = AttachMain.run(new String[]{
                "123", "agent.jar", "clean", "--id", id, "--confirm", "--evidence-dir", tempDir.toString()
        }, input("yes\n"), new PrintStream(out), new PrintStream(new ByteArrayOutputStream()), executor);

        assertEquals(1, code);
        assertTrue(executor.called);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("success=false"));
    }

    @Test
    void verify_loads_agent_and_prints_verify_result() throws Exception {
        String id = "F-123";
        VerifyExecutor.VerifyResult result = new VerifyExecutor.VerifyResult();
        result.findingId = id;
        result.stillPresent = false;
        result.verifiedAt = 123L;
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("verify-result.json"), result);
        RecordingExecutor executor = new RecordingExecutor();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = AttachMain.run(new String[]{
                "123", "agent.jar", "verify", "--id", id, "--evidence-dir", tempDir.toString()
        }, input(""), new PrintStream(out), new PrintStream(new ByteArrayOutputStream()), executor);

        assertEquals(0, code);
        assertTrue(executor.called);
        assertEquals("verify --id F-123 --evidence-dir " + tempDir, executor.agentArgs);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("stillPresent=false"));
    }

    @Test
    void verify_returns_nonzero_when_finding_is_still_present() throws Exception {
        String id = "F-123";
        VerifyExecutor.VerifyResult result = new VerifyExecutor.VerifyResult();
        result.findingId = id;
        result.stillPresent = true;
        result.verifiedAt = 123L;
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("verify-result.json"), result);
        RecordingExecutor executor = new RecordingExecutor();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = AttachMain.run(new String[]{
                "123", "agent.jar", "verify", "--id", id, "--evidence-dir", tempDir.toString()
        }, input(""), new PrintStream(out), new PrintStream(new ByteArrayOutputStream()), executor);

        assertEquals(1, code);
        assertTrue(executor.called);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("stillPresent=true"));
    }

    @org.junit.jupiter.api.Test
    void confirm_with_missing_plan_returns_2_and_does_not_invoke_agent() throws Exception {
        RecordingExecutor executor = new RecordingExecutor();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String id = "finding-no-plan";
        // No writeCleanPlan() call — plan file deliberately absent.

        int code = AttachMain.run(new String[]{
                "123", "agent.jar", "clean", "--id", id, "--confirm",
                "--evidence-dir", tempDir.toString()
        }, input(""), new PrintStream(new ByteArrayOutputStream()), new PrintStream(err), executor);

        assertEquals(2, code, "missing plan must return EXIT_USAGE (2)");
        assertFalse(executor.called, "agent must not be invoked when plan is missing");
        String stderr = err.toString(StandardCharsets.UTF_8);
        assertTrue(stderr.contains("plan file not found"),
                "stderr must explain the failure, was: " + stderr);
        assertTrue(stderr.contains("run --dry-run first"),
                "stderr must hint at the fix, was: " + stderr);
    }

    @Test
    void scan_without_output_injects_absolute_default_path() throws Exception {
        RecordingExecutor executor = new RecordingExecutor();
        int code = run(new String[]{"123", "agent.jar", "scan"}, "", executor);
        assertEquals(0, code);
        assertTrue(executor.called);
        assertTrue(executor.agentArgs.contains("--output "), executor.agentArgs);
        String out = executor.agentArgs.substring(executor.agentArgs.indexOf("--output ") + 9).trim();
        assertTrue(new java.io.File(out).isAbsolute(), "default output must be absolute: " + out);
        assertTrue(out.contains("memhunter-scan-") && out.endsWith(".json"), out);
    }

    @Test
    void scan_with_relative_output_is_made_absolute() throws Exception {
        RecordingExecutor executor = new RecordingExecutor();
        int code = run(new String[]{"123", "agent.jar", "scan", "--output", "rel.json"}, "", executor);
        assertEquals(0, code);
        String out = executor.agentArgs.substring(executor.agentArgs.indexOf("--output ") + 9).trim();
        assertTrue(new java.io.File(out).isAbsolute(), "user output must be made absolute: " + out);
        assertTrue(out.endsWith("rel.json"), out);
    }

    @Test
    void clean_command_does_not_inject_default_output() throws Exception {
        String id = "F-123";
        writeCleanPlan(id);
        CleanResult result = new CleanResult();
        result.findingId = id;
        result.success = true;
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("clean-result.json"), result);
        RecordingExecutor executor = new RecordingExecutor();
        run(new String[]{"123", "agent.jar", "clean", "--id", id, "--confirm",
                "--evidence-dir", tempDir.toString()}, "yes\n", executor);
        assertTrue(!executor.called || !executor.agentArgs.contains("--output"), executor.agentArgs);
    }

    private int run(String[] args, String stdin, RecordingExecutor executor) throws Exception {
        return AttachMain.run(args, input(stdin), new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), executor);
    }

    private ByteArrayInputStream input(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private void writeCleanPlan(String id) throws Exception {
        CleanPlan plan = new CleanPlan();
        plan.findingId = id;
        plan.type = "tomcat-filter";
        plan.targetName = "EvilFilter";
        plan.targetClass = "com.evil.X";
        plan.level = "critical";
        plan.score = 12;
        writeJson(tempDir.resolve("evidence").resolve(id).resolve("clean-plan.json"), plan);
    }

    private void writeJson(Path path, Object value) throws Exception {
        Files.createDirectories(path.getParent());
        new ObjectMapper().writeValue(path.toFile(), value);
    }

    static class RecordingExecutor extends AttachExecutor {
        boolean called;
        String pid;
        String agentJar;
        String agentArgs;

        @Override
        public void run(String pid, String agentJarPath, String agentArgs) {
            this.called = true;
            this.pid = pid;
            this.agentJar = new File(agentJarPath).getName();
            this.agentArgs = agentArgs;
        }
    }
}
