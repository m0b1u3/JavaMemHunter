package com.memhunter.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.memhunter.agent.model.OperationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StatusFileWriterTest {

    @Test
    void writesSuccessStatus(@TempDir Path dir) throws Exception {
        File f = dir.resolve("status.json").toFile();
        OperationStatus s = new OperationStatus();
        s.ok = true;
        s.command = "clean";
        s.id = "finding-x";
        s.message = "clean dry-run finished";
        StatusFileWriter.write(f.getAbsolutePath(), s);

        OperationStatus read = new ObjectMapper().readValue(f, OperationStatus.class);
        assertTrue(read.ok);
        assertEquals("clean", read.command);
        assertEquals("finding-x", read.id);
        assertEquals("clean dry-run finished", read.message);
    }

    @Test
    void writesFailureStatus(@TempDir Path dir) throws Exception {
        File f = dir.resolve("status.json").toFile();
        OperationStatus s = new OperationStatus();
        s.ok = false;
        s.command = "clean";
        s.id = "finding-x";
        s.error = "finding not located: finding-x";
        StatusFileWriter.write(f.getAbsolutePath(), s);

        OperationStatus read = new ObjectMapper().readValue(f, OperationStatus.class);
        assertFalse(read.ok);
        assertEquals("finding not located: finding-x", read.error);
    }

    @Test
    void nullPathIsNoOp() {
        OperationStatus s = new OperationStatus();
        s.ok = true;
        StatusFileWriter.write(null, s);
    }

    @Test
    void writeFailureDoesNotThrow() {
        OperationStatus s = new OperationStatus();
        s.ok = true;
        StatusFileWriter.write("/this/path/should/not/exist/__nope__/status.json", s);
    }
}
