package com.memhunter.agent.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CleanPlan {

    public String findingId;
    public String type;
    public String targetName;       // was filterName
    public String targetClass;      // was filterClass
    public String contextPath;
    public String level;
    public String evidenceDir;
    public String planFile;
    public Map<String, Object> details = new HashMap<>();   // replaces urlPatterns
    public List<String> steps;
    public int score;
    public boolean forced;
    public boolean rollbackSupported;
    public long generatedAt;
}
