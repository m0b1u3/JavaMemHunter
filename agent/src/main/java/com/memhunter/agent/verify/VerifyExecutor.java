package com.memhunter.agent.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.memhunter.agent.FindingLocator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class VerifyExecutor {

    private final Object tomcatContext;
    private final Object springContext;

    public VerifyExecutor(Object tomcatContext, Object springContext) {
        this.tomcatContext = tomcatContext;
        this.springContext = springContext;
    }

    /** @deprecated use {@link #VerifyExecutor(Object, Object)} */
    @Deprecated
    public VerifyExecutor(Object standardContext) {
        this(standardContext, null);
    }

    public VerifyResult verify(String findingId, Path baseDir) throws IOException {
        VerifyResult result = new VerifyResult();
        result.findingId = findingId;
        result.stillPresent = stillPresent(findingId);
        result.verifiedAt = System.currentTimeMillis();

        Path dir = baseDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("verify-result.json").toFile(), result);
        return result;
    }

    private boolean stillPresent(String findingId) {
        return FindingLocator.find(tomcatContext, springContext, findingId) != null;
    }

    /**
     * Records a verify result for a finding not located in any context — i.e. the component is
     * gone (a clean removed it). stillPresent=false, written without needing a context. Used by
     * the dispatch path when cross-context lookup yields nothing (v1.2).
     */
    public static VerifyResult writeAbsent(String findingId, Path baseDir) throws IOException {
        VerifyResult result = new VerifyResult();
        result.findingId = findingId;
        result.stillPresent = false;
        result.verifiedAt = System.currentTimeMillis();

        Path dir = baseDir.resolve("evidence").resolve(findingId);
        Files.createDirectories(dir);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(dir.resolve("verify-result.json").toFile(), result);
        return result;
    }

    public static class VerifyResult {
        public String findingId;
        public boolean stillPresent;
        public long verifiedAt;
    }
}
