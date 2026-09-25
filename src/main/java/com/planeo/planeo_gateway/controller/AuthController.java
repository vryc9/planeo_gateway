package com.planeo.planeo_gateway.controller;

import com.planeo.planeo_gateway.domain.SessionData;
import com.planeo.planeo_gateway.infrastructure.auth.AuthClient;
import com.planeo.planeo_gateway.infrastructure.redis.SessionStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

/**
 * The only auth-related endpoints the browser ever calls. Terminated here (not proxied to
 * planeo_auth) — the response never carries a JWT, only an opaque HttpOnly session cookie.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final AuthClient authClient;
    private final SessionStore sessionStore;
    private final SecretKey signingKey;
    private final String cookieName;
    private final long ttlSeconds;
    private final boolean cookieSecure;

    public AuthController(AuthClient authClient,
                           SessionStore sessionStore,
                           @Value("${jwt.secret}") String jwtSecret,
                           @Value("${planeo.session.cookie-name}") String cookieName,
                           @Value("${planeo.session.ttl-seconds}") long ttlSeconds,
                           @Value("${planeo.session.cookie-secure}") boolean cookieSecure) {
        this.authClient = authClient;
        this.sessionStore = sessionStore;
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.cookieName = cookieName;
        this.ttlSeconds = ttlSeconds;
        this.cookieSecure = cookieSecure;
    }

    public record LoginRequest(String username, String password) {}
    public record UserResponse(String username, String role) {}

    @PostMapping("/login")
    public Mono<ResponseEntity<UserResponse>> login(@RequestBody LoginRequest request) {
        return authClient.login(request.username(), request.password())
                .flatMap(tokens -> {
                    Claims claims = parseClaims(tokens.accessToken());
                    String role = claims.get("role", String.class);
                    String username = claims.getSubject();

                    SessionData session = new SessionData(
                            username, role, tokens.accessToken(), tokens.refreshToken(),
                            claims.getExpiration().toInstant());

                    String sessionId = newSessionId();

                    return sessionStore.save(sessionId, session)
                            .thenReturn(ResponseEntity.ok()
                                    .header(HttpHeaders.SET_COOKIE, buildCookie(sessionId).toString())
                                    .body(new UserResponse(username, role)));
                })
                .onErrorResume(ex -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange) {
        String sessionId = readSessionId(exchange);
        Mono<Boolean> clear = sessionId != null ? sessionStore.delete(sessionId) : Mono.just(true);

        return clear.thenReturn(ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, buildExpiredCookie().toString())
                .build());
    }

    @GetMapping("/me")
    public Mono<ResponseEntity<UserResponse>> me(ServerWebExchange exchange) {
        String sessionId = readSessionId(exchange);
        if (sessionId == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        }

        return sessionStore.find(sessionId)
                .map(session -> ResponseEntity.ok(new UserResponse(session.username(), session.role())))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    private Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
    }

    private String readSessionId(ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().getFirst(cookieName);
        return cookie != null ? cookie.getValue() : null;
    }

    private static String newSessionId() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private ResponseCookie buildCookie(String sessionId) {
        return ResponseCookie.from(cookieName, sessionId)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ofSeconds(ttlSeconds))
                .build();
    }

    private ResponseCookie buildExpiredCookie() {
        return ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
    }
}
