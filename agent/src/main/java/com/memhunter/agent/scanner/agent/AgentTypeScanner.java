package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;

import java.util.ArrayList;
import java.util.List;

/**
 * 聚合三个 agent 型内存马子检测器。
 * 接收原始 Instrumentation 对象（类型为 Object 以保持 agent 模块 Java 8 classpath 干净 ——
 * Instrumentation 在 java.instrument 模块里，作为 agent 运行时一定可用）。
 */
public class AgentTypeScanner {

    public List<Finding> scan(Object inst, ScanReport report) {
        List<Finding> all = new ArrayList<>();
        all.addAll(new TransformerScanner().scan(inst, report));
        all.addAll(new DynamicClassScanner().scan(inst, report));
        all.addAll(new BytecodeTamperScanner().scan(inst, report));
        return all;
    }
}
