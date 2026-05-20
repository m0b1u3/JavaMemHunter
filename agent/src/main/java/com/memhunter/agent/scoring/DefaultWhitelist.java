package com.memhunter.agent.scoring;

final class DefaultWhitelist {

    static final String[] FRAMEWORK_PACKAGES = {
            "org.springframework.",
            "org.apache.catalina.",
            "org.apache.tomcat.",
            "org.apache.coyote.",
            "org.apache.juli.",
            "com.fasterxml.jackson.",
            "ch.qos.logback.",
            "org.slf4j.",
            "com.zaxxer.hikari.",
            "javax.servlet.",
            "jakarta.servlet.",
            "org.hibernate.",
            "org.mybatis.",
            "com.alibaba.druid.",
            "io.netty."
    };

    static final String[] APM_AGENTS = {
            "com.taobao.arthas",
            "org.apache.skywalking",
            "io.opentelemetry",
            "com.navercorp.pinpoint",
            "co.elastic.apm",
            "com.newrelic",
            "org.datadoghq",
            "com.dynatrace"
    };

    static final String[] CODESOURCE_PATHS = {
            "/opt/app/",
            "/usr/local/tomcat/lib/",
            "/opt/tomcat/lib/"
    };

    static final String[] COMMON_CLASSLOADERS = {
            "org.springframework.boot.loader.LaunchedURLClassLoader",
            "org.apache.catalina.loader.ParallelWebappClassLoader",
            "org.apache.catalina.loader.WebappClassLoader",
            "jdk.internal.loader.ClassLoaders$AppClassLoader",
            "jdk.internal.loader.ClassLoaders$PlatformClassLoader",
            "sun.misc.Launcher$AppClassLoader",
            "sun.misc.Launcher$ExtClassLoader",
            "bootstrap"
    };

    private DefaultWhitelist() {}
}
