package com.memhunter.agent;

import java.lang.instrument.Instrumentation;

public class MemHunterAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        try {
            AgentArgs args = AgentArgs.parse(agentArgs);
            System.out.println("[memhunter] agent loaded, command=" + args.command);
            // Task 9 wires up the actual scan logic here
        } catch (Throwable t) {
            System.err.println("[memhunter] agent failed: " + t.getMessage());
            t.printStackTrace(System.err);
        }
    }
}
