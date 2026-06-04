package com.memhunter.agent.model;

import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class ScanContextTest {

    /** A loader that only serves one class's bytes as a resource, nothing else. */
    static class SingleResourceLoader extends ClassLoader {
        private final String resourcePath;
        private final byte[] bytes;
        SingleResourceLoader(String resourcePath, byte[] bytes) {
            super(null);  // no parent → does not delegate to app/system loader
            this.resourcePath = resourcePath;
            this.bytes = bytes;
        }
        @Override
        public java.io.InputStream getResourceAsStream(String name) {
            if (resourcePath.equals(name)) return new java.io.ByteArrayInputStream(bytes);
            return null;
        }
    }

    @Test
    void bytecodeOf_falls_back_to_injected_webapp_loader() throws Exception {
        // Real bytes of a known class, served only by a webapp loader the default path can't use.
        String cn = "com.memhunter.agent.model.ScanContextTest";
        String res = cn.replace('.', '/') + ".class";
        byte[] bytes = readResource(res);
        assertNotNull(bytes, "test prerequisite: own class bytes must be readable");

        SingleResourceLoader webapp = new SingleResourceLoader(res, bytes);

        // applicationContext=null and no TCCL match → default path may or may not read it, but the
        // webapp loader definitely can. Inject it and assert bytecode resolves.
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false,
                BaselineIndex.empty(), Collections.<ClassLoader>singletonList(webapp));

        BytecodeAnalysis a = ctx.bytecodeOf(cn);
        assertNotNull(a, "bytecode must resolve via the injected webapp loader");
    }

    @Test
    void bytecodeOf_returns_null_when_no_loader_can_read() {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false,
                BaselineIndex.empty(), Collections.<ClassLoader>emptyList());
        assertNull(ctx.bytecodeOf("com.nope.Missing_" + System.nanoTime()));
    }

    @Test
    void four_arg_constructor_still_works() {
        ScanContext ctx = new ScanContext(null, Whitelist.defaults(), false, BaselineIndex.empty());
        assertNull(ctx.bytecodeOf("com.nope.Missing_" + System.nanoTime()));
    }

    private static byte[] readResource(String res) throws Exception {
        try (java.io.InputStream in =
                     ScanContextTest.class.getClassLoader().getResourceAsStream(res)) {
            if (in == null) return null;
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }
}
