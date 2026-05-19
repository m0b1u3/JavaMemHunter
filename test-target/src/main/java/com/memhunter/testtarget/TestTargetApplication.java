package com.memhunter.testtarget;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"com.memhunter.testtarget", "com.memhunter.testinjector"})
public class TestTargetApplication {
    public static void main(String[] args) {
        SpringApplication.run(TestTargetApplication.class, args);
    }
}
