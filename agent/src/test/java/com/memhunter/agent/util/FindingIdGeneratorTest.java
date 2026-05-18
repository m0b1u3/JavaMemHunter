package com.memhunter.agent.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingIdGeneratorTest {

    @Test
    void same_inputs_produce_same_id() {
        String id1 = FindingIdGenerator.generate("class", "com.example.Abc", "");
        String id2 = FindingIdGenerator.generate("class", "com.example.Abc", "");
        assertEquals(id1, id2);
    }

    @Test
    void different_class_name_produces_different_id() {
        String id1 = FindingIdGenerator.generate("class", "com.example.Abc", "");
        String id2 = FindingIdGenerator.generate("class", "com.example.Xyz", "");
        assertNotEquals(id1, id2);
    }

    @Test
    void id_format_is_finding_type_hash8() {
        String id = FindingIdGenerator.generate("class", "com.example.Abc", "");
        assertTrue(id.matches("finding-class-[0-9a-f]{8}"), "Got: " + id);
    }
}
