package com.memhunter.agent.scanner.spring;

import java.util.List;

public interface ApplicationContextProvider {
    /** 返回所有可定位的 Spring ApplicationContext。失败返回空列表。 */
    List<Object> findAll(List<Object> tomcatContexts, List<Object> tomcatServletInstances);

    String name();
}
