package com.planeo.planeo_gateway.infrastructure.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.planeo.planeo_gateway.domain.SessionData;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Redis-backed session store: opaque session id -> {@link SessionData} (holds the JWTs the
 * browser never sees). Writing a session always (re)sets its TTL, which gives sessions a
 * sliding expiration on activity, bounded by planeo.session.ttl-seconds.
 */
@Component
public class SessionStore {

    private static final String KEY_PREFIX = "session:";

    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final Duration ttl;

    public SessionStore(ReactiveStringRedisTemplate redisTemplate,
                         ObjectMapper objectMapper,
                         @Value("${planeo.session.ttl-seconds}") long ttlSeconds) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    public Mono<Boolean> save(String sessionId, SessionData data) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(data))
                .flatMap(json -> redisTemplate.opsForValue().set(key(sessionId), json, ttl));
    }

    public Mono<SessionData> find(String sessionId) {
        return redisTemplate.opsForValue().get(key(sessionId))
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, SessionData.class)));
    }

    public Mono<Boolean> delete(String sessionId) {
        return redisTemplate.opsForValue().delete(key(sessionId));
    }

    private String key(String sessionId) {
        return KEY_PREFIX + sessionId;
    }
}
