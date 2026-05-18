package com.memhunter.attach;

import com.sun.tools.attach.VirtualMachine;

import java.io.File;

public class AttachExecutor {

    public void run(String pid, String agentJarPath, String agentArgs) throws Exception {
        File agentJar = new File(agentJarPath);
        if (!agentJar.exists()) {
            throw new IllegalArgumentException("Agent jar not found: " + agentJarPath);
        }
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            vm.loadAgent(agentJar.getAbsolutePath(), agentArgs);
            System.out.println("[memhunter] agent loaded successfully into PID " + pid);
        } finally {
            vm.detach();
        }
    }
}
