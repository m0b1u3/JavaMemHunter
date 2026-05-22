package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.FilterBackup;
import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Restores Tomcat StandardContext filter state from a FilterBackup snapshot.
 * Restore order is the reverse of Phase C forward order:
 *   forward: filterConfigs -> filterMaps -> filterDefs
 *   reverse: filterDefs    -> filterMaps -> filterConfigs
 *
 * Note: filterMaps positional index inside the original array is NOT preserved —
 * restored entries are appended to the end. Acceptable approximation since we
 * do not track original indices in FilterBackup.
 */
public class RollbackManager {

    @SuppressWarnings("unchecked")
    public void restore(Object standardContext, String filterName, FilterBackup backup) {
        if (standardContext == null || backup == null) {
            throw new RollbackFailedException("null context or backup",
                    new IllegalArgumentException("standardContext/backup is null"));
        }
        try {
            // 1. Restore filterDefs: put(filterName, backup.originalFilterDef)
            Object defsObj = ReflectUtil.tryReadField(standardContext, "filterDefs").orElse(null);
            Map<String, Object> defsCopy = new HashMap<>();
            if (defsObj instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) defsObj).entrySet()) {
                    defsCopy.put(String.valueOf(e.getKey()), e.getValue());
                }
            }
            if (backup.originalFilterDef != null && filterName != null) {
                defsCopy.put(filterName, backup.originalFilterDef);
            }
            ReflectUtil.setField(standardContext, "filterDefs", defsCopy);

            // 2. Restore filterMaps array: append backup.originalFilterMaps
            Object mapsField = ReflectUtil.tryReadField(standardContext, "filterMaps").orElse(null);
            Object[] currentArr;
            boolean nestedWrapper = false;
            Object wrapper = null;
            if (mapsField instanceof Object[]) {
                currentArr = (Object[]) mapsField;
            } else if (mapsField != null) {
                wrapper = mapsField;
                Object nested = ReflectUtil.tryReadField(wrapper, "array").orElse(null);
                currentArr = (nested instanceof Object[]) ? (Object[]) nested : new Object[0];
                nestedWrapper = true;
            } else {
                currentArr = new Object[0];
            }
            List<Object> combined = new ArrayList<>();
            for (Object o : currentArr) combined.add(o);
            if (backup.originalFilterMaps != null) {
                combined.addAll(backup.originalFilterMaps);
            }
            Object[] restored = combined.toArray(new Object[0]);
            if (nestedWrapper) {
                ReflectUtil.setField(wrapper, "array", restored);
            } else {
                ReflectUtil.setField(standardContext, "filterMaps", restored);
            }

            // 3. Restore filterConfigs: use backup.originalFilterConfigsMap as canonical
            Map<String, Object> configsRestored = new HashMap<>();
            if (backup.originalFilterConfigsMap != null) {
                configsRestored.putAll(backup.originalFilterConfigsMap);
            }
            ReflectUtil.setField(standardContext, "filterConfigs", configsRestored);
        } catch (RollbackFailedException e) {
            throw e;
        } catch (Throwable t) {
            throw new RollbackFailedException("rollback failed for filter " + filterName, t);
        }
    }
}
