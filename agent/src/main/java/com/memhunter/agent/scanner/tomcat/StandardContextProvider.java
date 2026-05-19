package com.memhunter.agent.scanner.tomcat;

import java.lang.instrument.Instrumentation;
import java.util.List;

public interface StandardContextProvider {
    /**
     * 返回可定位的全部 StandardContext 对象。
     * 失败应返回空列表，不抛异常。
     */
    List<Object> findAllContexts(Instrumentation inst);

    /** 用于日志/partialError 标识 */
    String name();
}
