package com.memhunter.agent.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    public Map<String, Object> attributes = new HashMap<>();

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public List<RuleHit> ruleHits;

    public static class RuleHit {
        public String rule;
        public int delta;

        public RuleHit() {}

        public RuleHit(String rule, int delta) {
            this.rule = rule;
            this.delta = delta;
        }
    }
}
