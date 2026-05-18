package com.memhunter.agent.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class FindingIdGenerator {

    private FindingIdGenerator() {}

    public static String generate(String type, String className, String discriminator) {
        String input = type + "|" + className + "|" + (discriminator == null ? "" : discriminator);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("finding-").append(type).append('-');
            for (int i = 0; i < 4; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
