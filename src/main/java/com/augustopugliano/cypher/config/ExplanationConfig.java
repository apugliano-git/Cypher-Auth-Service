package com.augustopugliano.cypher.config;

import org.springframework.context.annotation.*;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
public class ExplanationConfig {
    @Bean
    public ThreadPoolTaskExecutor explanationExecutor() {
        var executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2); executor.setMaxPoolSize(2); executor.setQueueCapacity(16);
        executor.setThreadNamePrefix("explanation-");
        return executor;
    }
}
