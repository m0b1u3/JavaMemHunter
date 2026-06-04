package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BenignComponentRuleTest {

    private Finding finding(String type, String className, String codeSource) {
        Finding f = new Finding();
        f.type = type;
        f.className = className;
        f.codeSource = codeSource;
        return f;
    }

    private ScanContext ctxWithBytecode(String className, String... calls) {
        ScanContext ctx = new ScanContext(null, null, false);
        Set<String> set = new HashSet<>();
        for (String c : calls) set.add(c);
        ctx.putBytecodeForTest(className, new BytecodeAnalysis(set));
        return ctx;
    }

    @Test
    void suppresses_normal_webapp_servlet() {
        Finding f = finding("tomcat-servlet", "com.example.UserServlet",
                "file:/opt/tomcat/webapps/app/WEB-INF/classes/");
        ScanContext ctx = ctxWithBytecode("com.example.UserServlet", "java/util/List#add");
        assertEquals(-10, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void does_not_suppress_null_codesource() {
        Finding f = finding("tomcat-servlet", "com.example.X", null);
        assertEquals(0, new BenignComponentRule().evaluate(f, null));
    }

    @Test
    void does_not_suppress_jsp_work_dir() {
        Finding f = finding("class-servlet", "org.apache.jsp.shell_jsp",
                "file:/opt/tomcat/work/Catalina/localhost/ROOT/");
        assertEquals(0, new BenignComponentRule().evaluate(f, null));
    }

    @Test
    void never_suppresses_agent_findings() {
        Finding f = finding("agent-bytecode-tampered", "javax.servlet.http.HttpServlet",
                "file:/opt/tomcat/lib/servlet-api.jar");
        assertEquals(0, new BenignComponentRule().evaluate(f, null));
    }

    @Test
    void does_not_suppress_component_with_malicious_bytecode() {
        Finding f = finding("tomcat-filter", "com.example.EvilFilter",
                "file:/opt/tomcat/webapps/app/WEB-INF/classes/");
        ScanContext ctx = ctxWithBytecode("com.example.EvilFilter", "java/lang/Runtime#exec");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void suppresses_camelcase_business_name_with_clean_bytecode() {
        // v0.12.1: the Shannon-entropy class-name gate was removed — it mislabelled normal
        // CamelCase webapp classes (RequestInfoExample, entropy 3.9) as random while missing
        // short real random names (Xdozy, entropy 2.3). Trust the bytecode-malice gate instead:
        // a clean-bytecode webapp component is suppressed regardless of name entropy.
        Finding f = finding("tomcat-servlet", "RequestInfoExample",
                "file:/opt/tomcat/webapps/examples/WEB-INF/classes/");
        ScanContext ctx = ctxWithBytecode("RequestInfoExample", "java/util/List#add");
        assertEquals(-10, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void still_does_not_suppress_high_entropy_name_when_bytecode_malicious() {
        // Even a webapp-located class is NOT suppressed if its bytecode is malicious — the
        // malice gate, not the name, is what blocks suppression.
        Finding f = finding("tomcat-servlet", "com.x.aXk9Qz7mP2wL",
                "file:/opt/tomcat/webapps/app/WEB-INF/classes/");
        ScanContext ctx = ctxWithBytecode("com.x.aXk9Qz7mP2wL", "java/lang/Runtime#exec");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }

    // --- v0.12 hardening (post code-review) ---

    @Test
    void does_not_suppress_temp_dir_jar() {
        // A jar loaded from /tmp is NOT a normal webapp codeSource — it must not be suppressed
        // even though the path contains ".jar".
        Finding f = finding("tomcat-filter", "com.example.LoggingFilter",
                "file:/tmp/evil.jar");
        ScanContext ctx = ctxWithBytecode("com.example.LoggingFilter", "java/util/List#add");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void does_not_suppress_var_tmp_jar() {
        Finding f = finding("tomcat-filter", "com.example.LoggingFilter",
                "file:/var/tmp/payload.jar");
        ScanContext ctx = ctxWithBytecode("com.example.LoggingFilter", "java/util/List#add");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void does_not_suppress_windows_temp_jar() {
        Finding f = finding("tomcat-filter", "com.example.LoggingFilter",
                "file:/C:/Windows/Temp/evil.jar");
        ScanContext ctx = ctxWithBytecode("com.example.LoggingFilter", "java/util/List#add");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }

    @Test
    void does_not_suppress_when_bytecode_unreadable() {
        // "bytecode missing" must NOT be treated as "bytecode proven clean".
        // A no-feature filter whose bytecode could not be read keeps its score
        // (no -10 suppression) so an analyst still sees it.
        Finding f = finding("tomcat-filter", "com.example.LoggingFilter",
                "file:/opt/tomcat/webapps/app/WEB-INF/classes/");
        ScanContext ctx = new ScanContext(null, null, false);  // no bytecode put → unreadable
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }
}
