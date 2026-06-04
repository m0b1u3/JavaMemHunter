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
    void does_not_suppress_high_entropy_class_name() {
        Finding f = finding("tomcat-servlet", "com.x.aXk9Qz7mP2wL",
                "file:/opt/tomcat/webapps/app/WEB-INF/classes/");
        ScanContext ctx = ctxWithBytecode("com.x.aXk9Qz7mP2wL", "java/util/List#add");
        assertEquals(0, new BenignComponentRule().evaluate(f, ctx));
    }
}
