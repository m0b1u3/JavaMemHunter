package com.memhunter.attach;

import com.memhunter.agent.model.CleanPlan;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class CleanInteractorTest {

    @Test
    void lowercase_yes_confirms() {
        assertTrue(prompt("yes\n"));
    }

    @Test
    void other_inputs_do_not_confirm() {
        assertFalse(prompt("no\n"));
        assertFalse(prompt("YES\n"));
        assertFalse(prompt("y\n"));
        assertFalse(prompt("\n"));
    }

    @Test
    void prompt_prints_clean_plan_summary() {
        CleanPlan plan = samplePlan();
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        new CleanInteractor().promptYes(input("no\n"), new PrintStream(out), plan);

        String text = out.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("F-123"));
        assertTrue(text.contains("EvilFilter"));
        assertTrue(text.contains("critical"));
    }

    private boolean prompt(String answer) {
        return new CleanInteractor().promptYes(input(answer), new PrintStream(new ByteArrayOutputStream()), samplePlan());
    }

    private ByteArrayInputStream input(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private CleanPlan samplePlan() {
        CleanPlan plan = new CleanPlan();
        plan.findingId = "F-123";
        plan.type = "tomcat-filter";
        plan.targetName = "EvilFilter";
        plan.targetClass = "com.evil.X";
        plan.contextPath = "/app";
        plan.score = 12;
        plan.level = "critical";
        return plan;
    }
}
