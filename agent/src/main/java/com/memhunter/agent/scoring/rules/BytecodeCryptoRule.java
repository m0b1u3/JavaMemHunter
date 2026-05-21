package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;

public class BytecodeCryptoRule implements ScoringRule {

    @Override public String name() { return "bytecode-crypto"; }

    @Override
    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        if (ctx == null) return 0;
        BytecodeAnalysis a = ctx.bytecodeOf(finding.className);
        if (a == null) return 0;
        if (a.hasMethodCall("javax/crypto/Cipher", "doFinal")) return 2;
        if (a.hasMethodCallByOwnerPrefix("java/util/Base64")) return 2;
        return 0;
    }
}
