package com.memhunter.attach;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.AgentLoadException;

import java.io.File;
import java.io.IOException;

public class AttachExecutor {

    public void run(String pid, String agentJarPath, String agentArgs) throws Exception {
        File agentJar = new File(agentJarPath);
        if (!agentJar.exists()) {
            throw new IllegalArgumentException("Agent jar not found: " + agentJarPath);
        }
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            try {
                vm.loadAgent(agentJar.getAbsolutePath(), agentArgs);
            } catch (AgentLoadException e) {
                if (!isBenignZeroReturn(e)) {
                    throw e;
                }
                System.out.println("[memhunter] agent reported zero return code via AgentLoadException; treating as success");
            }
            verifyExplicitOutput(agentArgs);
            System.out.println("[memhunter] agent loaded successfully into PID " + pid);
        } finally {
            vm.detach();
        }
    }

    static boolean isBenignZeroReturn(AgentLoadException e) {
        return e != null && "0".equals(e.getMessage());
    }

    static String explicitOutputPath(String agentArgs) {
        if (agentArgs == null || agentArgs.trim().isEmpty()) return null;
        String[] parts = agentArgs.trim().split("\\s+");
        for (int i = 0; i < parts.length - 1; i++) {
            if ("--output".equals(parts[i])) return parts[i + 1];
        }
        return null;
    }

    private static void verifyExplicitOutput(String agentArgs) throws IOException {
        String output = explicitOutputPath(agentArgs);
        if (output == null) return;
        File report = new File(output);
        if (!report.isFile() || report.length() == 0) {
            throw new IOException("Agent did not produce report: " + output);
        }
    }
}
