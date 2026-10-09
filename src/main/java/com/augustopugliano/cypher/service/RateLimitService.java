package com.augustopugliano.cypher.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;


@Service
public class RateLimitService {

    private final StringRedisTemplate redisTemplate;
    private final int windowMinutes;

    public RateLimitService(
            StringRedisTemplate redisTemplate,
            @Value("${cypher.rate-limit.window-minutes}") int windowMinutes) {
        this.redisTemplate = redisTemplate;
        if (windowMinutes < 1 || windowMinutes > 60) throw new IllegalArgumentException("Invalid rate limit window");
        this.windowMinutes = windowMinutes;
    }

    public long checkAndIncrement(String namespace, String key) {
        var script = new org.springframework.data.redis.core.script.DefaultRedisScript<Long>(
                "local n = redis.call('INCR', KEYS[1]); " +
                "if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return n", Long.class);
        Long attempts = redisTemplate.execute(script, java.util.List.of(namespace + key), Integer.toString(windowMinutes * 60));
        if (attempts == null) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE);
        return attempts;
    }
}
