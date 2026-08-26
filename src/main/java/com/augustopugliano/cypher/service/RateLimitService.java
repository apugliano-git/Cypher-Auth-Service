package com.augustopugliano.cypher.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RateLimitService {

    private final StringRedisTemplate redisTemplate;
    private final int windowMinutes;

    public RateLimitService(
            StringRedisTemplate redisTemplate,
            @Value("${cypher.rate-limit.window-minutes}") int windowMinutes) {
        this.redisTemplate = redisTemplate;
        this.windowMinutes = windowMinutes;
    }

    public long checkAndIncrement(String key) {
        String redisKey = "login_attempts:" + key;
        Long attempts = redisTemplate.opsForValue().increment(redisKey);
        
        if (attempts != null && attempts == 1) {
            redisTemplate.expire(redisKey, Duration.ofMinutes(windowMinutes));
        }
        
        return attempts != null ? attempts : 0;
    }

    public void reset(String key) {
        String redisKey = "login_attempts:" + key;
        redisTemplate.delete(redisKey);
    }
}
