package com.memhunter.agent.scoring;

import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BytecodeMaliceCheckTest {

    private BytecodeAnalysis withCalls(String... calls) {
        Set<String> s = new HashSet<>();
        for (String c : calls) s.add(c);
        return new BytecodeAnalysis(s);
    }

    @Test
    void flags_runtime_exec() {
        assertTrue(BytecodeMaliceCheck.hasMalice(withCalls("java/lang/Runtime#exec")));
    }

    @Test
    void flags_processbuilder_start() {
        assertTrue(BytecodeMaliceCheck.hasMalice(withCalls("java/lang/ProcessBuilder#start")));
    }

    @Test
    void flags_defineclass() {
        assertTrue(BytecodeMaliceCheck.hasMalice(withCalls("java/lang/ClassLoader#defineClass")));
    }

    @Test
    void flags_cipher_dofinal() {
        assertTrue(BytecodeMaliceCheck.hasMalice(withCalls("javax/crypto/Cipher#doFinal")));
    }

    @Test
    void ignores_common_business_calls() {
        assertFalse(BytecodeMaliceCheck.hasMalice(withCalls(
            "java/lang/String#equals",
            "java/util/List#add",
            "java/lang/reflect/Method#invoke",
            "java/lang/Class#getDeclaredMethod")));
    }

    @Test
    void null_analysis_is_not_malicious() {
        assertFalse(BytecodeMaliceCheck.hasMalice((BytecodeAnalysis) null));
    }

    @Test
    void readable_bytecode_true_only_when_present_in_context() {
        com.memhunter.agent.model.ScanContext ctx =
                new com.memhunter.agent.model.ScanContext(null, null, false);
        ctx.putBytecodeForTest("com.example.Foo", withCalls("java/util/List#add"));
        assertTrue(BytecodeMaliceCheck.hasReadableBytecode("com.example.Foo", ctx));
        assertFalse(BytecodeMaliceCheck.hasReadableBytecode("com.example.Missing", ctx));
        assertFalse(BytecodeMaliceCheck.hasReadableBytecode("com.example.Foo", null));
        assertFalse(BytecodeMaliceCheck.hasReadableBytecode(null, ctx));
    }
}
