package com.memhunter.agent.model;

import java.util.List;

public class CleanPlan {

    public String findingId;
    public String type;
    public String filterName;
    public String filterClass;
    public String contextPath;
    public String level;
    public String evidenceDir;
    public String planFile;
    public List<String> urlPatterns;
    public List<String> steps;
    public int score;
    public boolean forced;
    public boolean rollbackSupported;
    public long generatedAt;
}
