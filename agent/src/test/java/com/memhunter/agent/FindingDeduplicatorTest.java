package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FindingDeduplicatorTest {

    private Finding f(String type, String className, int score) {
        Finding x = new Finding();
        x.type = type;
        x.className = className;
        x.score = score;
        return x;
    }

    @Test
    void same_classname_keeps_highest_score() {
        Finding hi = f("tomcat-filter", "org.apache.coyote.X", 16);
        Finding lo = f("class-filter", "org.apache.coyote.X", 13);
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(lo, hi));
        assertEquals(1, out.size());
        assertEquals(16, out.get(0).score);
        assertEquals("tomcat-filter", out.get(0).type);
    }

    @Test
    void tie_score_prefers_one_with_path_attribute() {
        Finding withPath = f("tomcat-filter", "com.x.Y", 10);
        withPath.attributes.put("urlPatterns", Arrays.asList("/*"));
        Finding noPath = f("class-filter", "com.x.Y", 10);
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(noPath, withPath));
        assertEquals(1, out.size());
        assertEquals("tomcat-filter", out.get(0).type);
    }

    @Test
    void tie_score_no_path_keeps_earlier() {
        Finding first = f("class-filter", "com.x.Z", 8);
        Finding second = f("class-servlet", "com.x.Z", 8);
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(first, second));
        assertEquals(1, out.size());
        assertEquals("class-filter", out.get(0).type);
    }

    @Test
    void null_classname_findings_all_kept() {
        Finding a = f("tomcat-servlet", null, 8);
        Finding b = f("tomcat-servlet", null, 8);
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(a, b));
        assertEquals(2, out.size());
    }

    @Test
    void distinct_classnames_all_kept() {
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(
                f("tomcat-filter", "com.a.A", 16),
                f("tomcat-filter", "com.b.B", 16)));
        assertEquals(2, out.size());
    }

    @Test
    void empty_and_null_input_return_empty() {
        assertTrue(FindingDeduplicator.dedupe(new ArrayList<>()).isEmpty());
        assertTrue(FindingDeduplicator.dedupe(null).isEmpty());
    }

    @Test
    void output_order_classnames_first_seen_then_null_class() {
        Finding n = f("tomcat-servlet", null, 8);
        Finding a = f("class-filter", "com.a.A", 5);
        Finding b = f("class-filter", "com.b.B", 5);
        List<Finding> out = FindingDeduplicator.dedupe(Arrays.asList(n, a, b));
        assertEquals(3, out.size());
        assertEquals("com.a.A", out.get(0).className);
        assertEquals("com.b.B", out.get(1).className);
        assertNull(out.get(2).className);
    }
}
