package com.memhunter.agent.cleaner;

/**
 * Which runtime context a cleaner factory needs. CleanerRegistry uses this to
 * route the correct context object (Tomcat StandardContext vs Spring
 * ApplicationContext) to each cleaner at dispatch time.
 */
public enum ContextKind {
    TOMCAT,
    SPRING
}
