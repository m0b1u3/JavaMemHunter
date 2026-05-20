package com.memhunter.agent.model;

import com.memhunter.agent.scoring.Whitelist;

public class ScanContext {
    public final Object applicationContext;
    public final Whitelist whitelist;
    public final boolean explain;

    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain) {
        this.applicationContext = applicationContext;
        this.whitelist = whitelist;
        this.explain = explain;
    }
}
