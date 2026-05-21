package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytecodeCryptoRuleTest {

    private final BytecodeCryptoRule rule = new BytecodeCryptoRule();

    private Finding f() {
        Finding f = new Finding();
        f.className = "com.X";
        f.type = "class-filter";
        return f;
    }

    private ScanContext ctxWithCalls(String... calls) {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);
        ctx.putBytecodeForTest("com.X",
                new BytecodeAnalysis(new HashSet<>(Arrays.asList(calls))));
        return ctx;
    }

    @Test
    void cipher_doFinal_hits() {
        ScanContext ctx = ctxWithCalls("javax/crypto/Cipher#doFinal");
        assertEquals(2, rule.evaluate(f(), ctx));
    }

    @Test
    void base64_decoder_hits() {
        ScanContext ctx = ctxWithCalls("java/util/Base64$Decoder#decode");
        assertEquals(2, rule.evaluate(f(), ctx));
    }

    @Test
    void unrelated_calls_miss() {
        ScanContext ctx = ctxWithCalls("java/util/HashMap#put");
        assertEquals(0, rule.evaluate(f(), ctx));
    }
}
