package com.memhunter.agent.scanner;

/**
 * Reverse-maps a Tomcat-compiled JSP class name to its .jsp access URL.
 *
 * <p>Tomcat compiles {@code /admin/x.jsp} to class {@code org.apache.jsp.admin.x_jsp}. This
 * recovers the URL from the class name so a JSP webshell (a file-based shell, not an in-memory
 * one) shows its access path in the scan summary. Escaped characters in the class name
 * ({@code _002d} etc.) are left as-is — webshell filenames rarely use special characters.
 */
public final class JspPathResolver {

    private JspPathResolver() {}

    private static final String PREFIX = "org.apache.jsp.";
    private static final String SUFFIX = "_jsp";

    /** @return the .jsp URL, or null if className is not a Tomcat-compiled JSP class. */
    public static String toJspUrl(String className) {
        if (className == null || !className.startsWith(PREFIX)) return null;
        String rest = className.substring(PREFIX.length());
        if (!rest.endsWith(SUFFIX)) return null;
        String body = rest.substring(0, rest.length() - SUFFIX.length());
        if (body.isEmpty()) return null;
        return "/" + body.replace('.', '/') + ".jsp";
    }
}
