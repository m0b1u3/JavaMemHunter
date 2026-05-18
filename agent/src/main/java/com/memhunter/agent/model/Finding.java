package com.memhunter.agent.model;

import java.util.ArrayList;
import java.util.List;

public class Finding {

    public String id;
    public String type;
    public String level;
    public int score;
    public String name;
    public String className;
    public String codeSource;
    public String classLoader;
    public List<String> reasons = new ArrayList<>();
    public String recommendation;
}
