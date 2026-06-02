package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class TransformerScannerTest {

    static class FakeTransformerManager {
        public Object[] mTransformers;
        FakeTransformerManager(Object[] t) { this.mTransformers = t; }
    }

    static class FakeInstrumentation {
        public Object mTransformerManager;
        FakeInstrumentation(Object tm) { this.mTransformerManager = tm; }
    }

    static class EvildoerTransformer implements ClassFileTransformer {
        public byte[] transform(ClassLoader l, String n, Class<?> c, ProtectionDomain pd, byte[] b) { return null; }
    }

    @Test
    void unknown_transformer_is_reported_as_agent_transformer() {
        EvildoerTransformer evil = new EvildoerTransformer();
        Object inst = new FakeInstrumentation(new FakeTransformerManager(new Object[]{evil}));
        List<Finding> findings = new TransformerScanner().scan(inst, new ScanReport());
        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("agent-transformer", f.type);
        assertEquals("high", f.level);
        assertEquals(10, f.score);
        assertEquals(evil.getClass().getName(), f.attributes.get("transformerClass"));
    }

    @Test
    void memhunter_transformer_is_whitelisted_not_reported() {
        // TransformerScanner itself is in com.memhunter.* → whitelisted
        Object inst = new FakeInstrumentation(new FakeTransformerManager(new Object[]{new TransformerScanner()}));
        List<Finding> findings = new TransformerScanner().scan(inst, new ScanReport());
        assertTrue(findings.isEmpty(), "com.memhunter.* must be whitelisted");
    }

    @Test
    void empty_transformer_list_returns_no_findings() {
        Object inst = new FakeInstrumentation(new FakeTransformerManager(new Object[0]));
        assertTrue(new TransformerScanner().scan(inst, new ScanReport()).isEmpty());
    }

    @Test
    void null_transformer_array_returns_no_findings() {
        Object inst = new FakeInstrumentation(new FakeTransformerManager(null));
        assertTrue(new TransformerScanner().scan(inst, new ScanReport()).isEmpty());
    }

    @Test
    void missing_mTransformerManager_field_records_partial_error() {
        Object inst = new Object();  // no fields
        ScanReport report = new ScanReport();
        List<Finding> findings = new TransformerScanner().scan(inst, report);
        assertTrue(findings.isEmpty());
        assertFalse(report.partialErrors.isEmpty(), "must record partialError on reflection failure");
    }
}
