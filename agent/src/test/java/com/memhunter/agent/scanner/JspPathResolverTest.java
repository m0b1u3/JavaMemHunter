package com.memhunter.agent.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JspPathResolverTest {

    @Test
    void root_jsp_maps_to_slash_jsp() {
        assertEquals("/wwwwxxx.jsp", JspPathResolver.toJspUrl("org.apache.jsp.wwwwxxx_jsp"));
        assertEquals("/shell.jsp", JspPathResolver.toJspUrl("org.apache.jsp.shell_jsp"));
    }

    @Test
    void subdir_jsp_maps_package_dots_to_slashes() {
        assertEquals("/admin/x.jsp", JspPathResolver.toJspUrl("org.apache.jsp.admin.x_jsp"));
        assertEquals("/a/b/c.jsp", JspPathResolver.toJspUrl("org.apache.jsp.a.b.c_jsp"));
    }

    @Test
    void non_jsp_class_returns_null() {
        assertNull(JspPathResolver.toJspUrl("com.example.Foo"));
        assertNull(JspPathResolver.toJspUrl("org.apache.coyote.ser.SerializerCache"));
    }

    @Test
    void jsp_prefix_but_not_jsp_suffix_returns_null() {
        assertNull(JspPathResolver.toJspUrl("org.apache.jsp.weird"));
    }

    @Test
    void prefix_only_or_empty_returns_null() {
        assertNull(JspPathResolver.toJspUrl("org.apache.jsp."));
        assertNull(JspPathResolver.toJspUrl("org.apache.jsp._jsp"));
        assertNull(JspPathResolver.toJspUrl(null));
        assertNull(JspPathResolver.toJspUrl(""));
    }
}
