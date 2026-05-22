package com.memhunter.agent.model;

import java.util.List;
import java.util.Map;

/**
 * In-memory snapshot of Tomcat filter state used by RollbackManager.
 * Not serialized — FilterDef/FilterMap/ApplicationFilterConfig are runtime-loaded,
 * so fields are typed as Object/List&lt;Object&gt;/Map&lt;String, Object&gt;.
 */
public class FilterBackup {

    public Object originalFilterDef;
    public List<Object> originalFilterMaps;
    public Object originalFilterConfig;
    public Map<String, Object> originalFilterConfigsMap;
}
