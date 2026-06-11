package com.memhunter.attach;

import com.memhunter.agent.model.OperationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StatusFileReaderTest {

    @Test
    void readsOkStatus(@TempDir Path dir) throws Exception {
        File f = dir.resolve("status.json").toFile();
        Files.write(f.toPath(),
                "{\"ok\":true,\"command\":\"clean\",\"id\":\"x\",\"message\":\"done\"}".getBytes());
        OperationStatus s = StatusFileReader.read(f.getAbsolutePath());
        assertNotNull(s);
        assertTrue(s.ok);
    }

    @Test
    void readsFailureStatus(@TempDir Path dir) throws Exception {
        File f = dir.resolve("status.json").toFile();
        Files.write(f.toPath(),
                "{\"ok\":false,\"command\":\"clean\",\"id\":\"x\",\"error\":\"finding not located: x\"}".getBytes());
        OperationStatus s = StatusFileReader.read(f.getAbsolutePath());
        assertNotNull(s);
        assertFalse(s.ok);
        org.junit.jupiter.api.Assertions.assertEquals("finding not located: x", s.error);
    }

    @Test
    void missingFileReturnsNull() {
        assertNull(StatusFileReader.read("/no/such/status-file-xyz.json"));
    }

    @Test
    void nullPathReturnsNull() {
        assertNull(StatusFileReader.read(null));
    }
}
