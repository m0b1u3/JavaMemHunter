package com.memhunter.agent.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatFilterScanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class VerifyExecutor {

    private final Object standardContext;

    public VerifyExecutor(Object standardContext) {
        this.standardContext = standardContext;
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
        List<Finding> findings = new TomcatFilterScanner(standardContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f != null && findingId != null && findingId.equals(f.id)) {
                return true;
            }
        }
        return false;
    }

    public static class VerifyResult {
        public String findingId;
        public boolean stillPresent;
        public long verifiedAt;
    }
}
