package com.memhunter.attach;

public class AttachMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }
        String cmd = args[0];
        if ("list".equals(cmd)) {
            new JvmProcessLister().printAll();
            return;
        }
        if (args.length < 3) {
            printUsage();
            System.exit(1);
        }
        String pid = args[0];
        String agentJar = args[1];
        StringBuilder agentArgs = new StringBuilder(args[2]);
        for (int i = 3; i < args.length; i++) {
            agentArgs.append(' ').append(args[i]);
        }
        new AttachExecutor().run(pid, agentJar, agentArgs.toString());
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java -jar memhunter-attach.jar list");
        System.err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> scan [--output <file>]");
    }
}
