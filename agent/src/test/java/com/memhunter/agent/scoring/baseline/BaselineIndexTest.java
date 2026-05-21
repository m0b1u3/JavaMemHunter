package com.memhunter.agent.scoring.baseline;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class BaselineIndexTest {

    @Test
    void empty_index_contains_nothing() {
        BaselineIndex idx = BaselineIndex.empty();
        assertTrue(idx.isEmpty());
        assertEquals(0, idx.size());
        assertFalse(idx.contains("any"));
        assertFalse(idx.contains(null));
    }

    @Test
    void contains_returns_true_for_known_id() {
        BaselineIndex idx = new BaselineIndex(new HashSet<>(Arrays.asList(
                "finding-class-filter-aaaabbbb",
                "finding-tomcat-filter-ccccdddd")));
        assertTrue(idx.contains("finding-class-filter-aaaabbbb"));
        assertTrue(idx.contains("finding-tomcat-filter-ccccdddd"));
    }

    @Test
    void contains_returns_false_for_unknown_id() {
        BaselineIndex idx = new BaselineIndex(new HashSet<>(Arrays.asList("finding-a-b")));
        assertFalse(idx.contains("finding-x-y"));
    }

    @Test
    void contains_null_id_returns_false() {
        BaselineIndex idx = new BaselineIndex(new HashSet<>(Arrays.asList("finding-a-b")));
        assertFalse(idx.contains(null));
    }

    @Test
    void size_reports_number_of_ids() {
        BaselineIndex idx = new BaselineIndex(new HashSet<>(Arrays.asList("a", "b", "c")));
        assertEquals(3, idx.size());
        assertFalse(idx.isEmpty());
    }
}
