package com.memhunter.it;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Forks memhunter-attach.jar as a subprocess. Captures combined stdout/stderr to attach-*.log */
final class AttachRunner {

    private AttachRunner() {}

    static int run(String pid, String... command) throws IOException, InterruptedException {
        return runWithStdin(pid, "", command);
    }

    static int runWithStdin(String pid, String stdinPayload, String... command)
            throws IOException, InterruptedException {
        String attachJar = required("attach.jar");
        String agentJar  = required("agent.jar");

        List<String> args = new ArrayList<>();
        args.add("java");
        args.add("-jar");
        args.add(attachJar);
        args.add(pid);
        args.add(agentJar);
        for (String c : command) args.add(c);

        Path evDir = Paths.get(System.getProperty("user.dir"), "target", "evidence",
                System.getProperty("profile.id", "sb27")).toAbsolutePath();
        Files.createDirectories(evDir);
        Path log = evDir.resolve("attach-" + command[0] + "-" + System.nanoTime() + ".log");

        ProcessBuilder pb = new ProcessBuilder(args).redirectErrorStream(true)
                .redirectOutput(log.toFile());
        Process p = pb.start();
        if (stdinPayload != null && !stdinPayload.isEmpty()) {
            p.getOutputStream().write(stdinPayload.getBytes());
            p.getOutputStream().close();
        }
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("attach " + command[0] + " timed out; see " + log);
        }
        return p.exitValue();
    }

    private static String required(String name) {
        String v = System.getProperty(name);
        if (v == null || v.isEmpty()) {
            throw new IllegalStateException("-D" + name + " required");
        }
        return v;
    }
}
