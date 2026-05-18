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
        // Task 4 extends: <pid> <agent-jar> <subcommand>
        printUsage();
        System.exit(1);
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java -jar memhunter-attach.jar list");
        System.err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> scan [--output <file>]");
    }
}
