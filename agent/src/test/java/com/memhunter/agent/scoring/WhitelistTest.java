package com.memhunter.agent.scoring;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class WhitelistTest {

    @Test
    void defaults_recognize_framework_packages() {
        Whitelist w = Whitelist.defaults();
        assertTrue(w.isFrameworkPackage("org.springframework.web.servlet.DispatcherServlet"));
        assertTrue(w.isFrameworkPackage("org.apache.tomcat.websocket.server.WsFilter"));
        assertFalse(w.isFrameworkPackage("com.attacker.FakeFilter"));
    }

    @Test
    void defaults_recognize_apm_agents() {
        Whitelist w = Whitelist.defaults();
        assertTrue(w.isApmAgent("com.taobao.arthas.core.Arthas"));
        assertTrue(w.isApmAgent("org.apache.skywalking.apm.agent.core.SkyWalking"));
        assertFalse(w.isApmAgent("com.attacker.FakeFilter"));
    }

    @Test
    void business_packages_empty_by_default() {
        assertFalse(Whitelist.defaults().isBusinessPackage("com.mycompany.app.HelloController"));
    }

    @Test
    void load_from_file_adds_entries(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("custom.txt");
        Files.write(file, Arrays.asList(
                "# user-defined business",
                "business:com.mycompany.",
                "framework:com.acme.shared.",
                "agent:com.custom.tracer",
                "codesource:/opt/myapp/",
                "",
                "garbage line without colon"
        ));
        Whitelist w = Whitelist.defaults();
        w.loadFromFile(file.toString());
        assertTrue(w.isBusinessPackage("com.mycompany.app.HelloController"));
        assertTrue(w.isFrameworkPackage("com.acme.shared.Util"));
        assertTrue(w.isApmAgent("com.custom.tracer.Foo"));
        assertTrue(w.isTrustedCodeSource("/opt/myapp/lib/foo.jar"));
    }

    @Test
    void common_classloaders_include_spring_boot_launched() {
        assertTrue(Whitelist.defaults().commonClassLoaders().contains(
                "org.springframework.boot.loader.LaunchedURLClassLoader"));
    }
}
