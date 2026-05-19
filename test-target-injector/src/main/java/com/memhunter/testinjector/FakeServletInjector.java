package com.memhunter.testinjector;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FakeServletInjector {

    private final ServletContext servletContext;

    public FakeServletInjector(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void inject() {
        ServletRegistration.Dynamic reg =
                servletContext.addServlet("FakeServlet", new FakeServlet());
        if (reg != null) {
            reg.addMapping("/fake-api");
        }
    }

    public static class FakeServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.getWriter().write("fake servlet response");
        }
    }
}
