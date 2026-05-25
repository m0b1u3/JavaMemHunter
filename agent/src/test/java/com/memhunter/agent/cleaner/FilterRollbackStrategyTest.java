package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.FilterBackup;
import com.memhunter.agent.util.ReflectUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FilterRollbackStrategyTest {

    public static class FakeContext {
        public HashMap<String, Object> filterDefs = new HashMap<>();
        public FakeFilterMaps filterMaps = new FakeFilterMaps();
        public HashMap<String, Object> filterConfigs = new HashMap<>();
    }
    public static class FakeFilterMaps {
        public Object[] array = new Object[0];
    }
    public static class TypedFakeContext {
        public HashMap<String, Object> filterDefs = new HashMap<>();
        public TypedFakeFilterMaps filterMaps = new TypedFakeFilterMaps();
        public HashMap<String, Object> filterConfigs = new HashMap<>();
    }
    public static class TypedFakeFilterMaps {
        public FakeFilterMap[] array = new FakeFilterMap[0];
    }
    public static class FakeFilterDef {
        public String filterName;
        public String filterClass;
    }
    public static class FakeFilterMap {
        public String filterName;
    }
    public static class FakeFilterConfig {
        public Object filter;
    }

    private FakeContext ctx;
    private FilterBackup backup;
    private FakeFilterDef evilDef;
    private FakeFilterMap evilMap;
    private FakeFilterConfig evilCfg;

    @BeforeEach
    void setUp() {
        ctx = new FakeContext();
        evilDef = new FakeFilterDef();
        evilDef.filterName = "EvilFilter";
        evilDef.filterClass = "com.evil.X";
        evilMap = new FakeFilterMap();
        evilMap.filterName = "EvilFilter";
        evilCfg = new FakeFilterConfig();
        evilCfg.filter = new Object();

        backup = new FilterBackup();
        backup.originalFilterDef = evilDef;
        backup.originalFilterMaps = new ArrayList<>(Collections.singletonList(evilMap));
        backup.originalFilterConfig = evilCfg;
        Map<String, Object> origConfigs = new HashMap<>();
        origConfigs.put("EvilFilter", evilCfg);
        backup.originalFilterConfigsMap = origConfigs;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readMap(String f) {
        return (Map<String, Object>) ReflectUtil.tryReadField(ctx, f).orElse(null);
    }

    @Test
    void rollbackRestoresFilterDef() {
        // Simulate post-Phase-C state: filterDefs missing EvilFilter
        ctx.filterDefs = new HashMap<>(); // empty
        new FilterRollbackStrategy(ctx, "EvilFilter", backup).restore();
        Map<String, Object> defs = readMap("filterDefs");
        assertSame(evilDef, defs.get("EvilFilter"));
    }

    @Test
    void rollbackRestoresFilterConfigs() {
        ctx.filterConfigs = new HashMap<>();
        new FilterRollbackStrategy(ctx, "EvilFilter", backup).restore();
        Map<String, Object> configs = readMap("filterConfigs");
        assertSame(evilCfg, configs.get("EvilFilter"));
    }

    @Test
    void rollbackRestoresFilterMapsArray() {
        ctx.filterMaps.array = new Object[0]; // simulate removal
        new FilterRollbackStrategy(ctx, "EvilFilter", backup).restore();
        assertEquals(1, ctx.filterMaps.array.length);
        assertSame(evilMap, ctx.filterMaps.array[0]);
    }

    @Test
    void rollbackRestoresTypedFilterMapsArray() {
        TypedFakeContext typed = new TypedFakeContext();
        typed.filterMaps.array = new FakeFilterMap[0];

        new FilterRollbackStrategy(typed, "EvilFilter", backup).restore();

        assertEquals(1, typed.filterMaps.array.length);
        assertSame(evilMap, typed.filterMaps.array[0]);
    }

    @Test
    void rollbackOnFullyEmptyContextStillSucceeds() {
        ctx.filterDefs = new HashMap<>();
        ctx.filterConfigs = new HashMap<>();
        ctx.filterMaps.array = new Object[0];

        new FilterRollbackStrategy(ctx, "EvilFilter", backup).restore();

        assertTrue(readMap("filterDefs").containsKey("EvilFilter"));
        assertTrue(readMap("filterConfigs").containsKey("EvilFilter"));
        assertEquals(1, ctx.filterMaps.array.length);
    }

    @Test
    void rollbackPreservesBystanders() {
        FakeFilterDef good = new FakeFilterDef();
        good.filterName = "GoodFilter";
        ctx.filterDefs.put("GoodFilter", good);
        FakeFilterConfig goodCfg = new FakeFilterConfig();
        ctx.filterConfigs.put("GoodFilter", goodCfg);
        FakeFilterMap goodMap = new FakeFilterMap();
        goodMap.filterName = "GoodFilter";
        ctx.filterMaps.array = new Object[]{ goodMap };
        // backup.originalFilterConfigsMap holds the canonical pre-clean configs; in real flow
        // it would have included GoodFilter. Simulate that:
        backup.originalFilterConfigsMap.put("GoodFilter", goodCfg);

        new FilterRollbackStrategy(ctx, "EvilFilter", backup).restore();

        Map<String, Object> defs = readMap("filterDefs");
        assertTrue(defs.containsKey("GoodFilter"));
        assertTrue(defs.containsKey("EvilFilter"));
        Map<String, Object> configs = readMap("filterConfigs");
        assertTrue(configs.containsKey("GoodFilter"));
        assertTrue(configs.containsKey("EvilFilter"));
        // filterMaps: goodMap + restored evilMap
        assertEquals(2, ctx.filterMaps.array.length);
        assertTrue(Arrays.asList(ctx.filterMaps.array).contains(goodMap));
        assertTrue(Arrays.asList(ctx.filterMaps.array).contains(evilMap));
    }

    @Test
    void rollbackThrowsOnNullContext() {
        assertThrows(RollbackFailedException.class,
                () -> new FilterRollbackStrategy(null, "EvilFilter", backup).restore());
    }
}
