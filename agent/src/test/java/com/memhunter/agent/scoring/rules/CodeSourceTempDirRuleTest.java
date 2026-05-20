package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.Whitelist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CodeSourceTempDirRuleTest {
    private final CodeSourceTempDirRule rule = new CodeSourceTempDirRule();
    private final ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false);

    @Test
    void hits_windows_temp_codesource() {
        Finding f = finding("file:/C:/Users/Admin/AppData/Local/Temp/x.jar");
        assertEquals(3, rule.evaluate(f, ctx));
    }

    @Test
    void hits_unix_temp_codesource() {
        assertEquals(3, rule.evaluate(finding("file:/tmp/x.jar"), ctx));
        assertEquals(3, rule.evaluate(finding("file:/var/tmp/x.jar"), ctx));
    }

    @Test
    void misses_normal_codesource() {
        assertEquals(0, rule.evaluate(finding("file:/opt/app/app.jar"), ctx));
    }

    private Finding finding(String codeSource) {
        Finding f = new Finding();
        f.codeSource = codeSource;
        return f;
    }
}
