package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;

/**
 * Tomcat-specific cleaner base. Holds the StandardContext reference and provides
 * the Tomcat contextPath. All Phase A/D/E orchestration lives in AbstractCleaner.
 */
public abstract class AbstractTomcatCleaner extends AbstractCleaner {

    protected final Object standardContext;

    protected AbstractTomcatCleaner(Object standardContext) {
        this.standardContext = standardContext;
    }

    @Override
    protected String contextPathOf(Finding finding) {
        return String.valueOf(finding.attributes.getOrDefault("contextPath", ""));
    }
}
