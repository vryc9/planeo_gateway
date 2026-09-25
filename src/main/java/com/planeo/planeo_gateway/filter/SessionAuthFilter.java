package com.planeo.planeo_gateway.filter;

import com.planeo.planeo_gateway.domain.SessionData;
import com.planeo.planeo_gateway.infrastructure.auth.AuthClient;
import com.planeo.planeo_gateway.infrastructure.redis.SessionStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Resolves the opaque session cookie against Redis, transparently refreshes the JWT pair when
 * it is close to expiry, and injects Authorization and X-Auth-Username / X-Auth-Role headers
 * before routing to the microservices. Any of those headers sent by the client itself is
 * always stripped first: downstream services trust them blindly, so the gateway must be the
 * only thing that can set them.
 */
@Component
public class SessionAuthFilter implements GlobalFilter, Ordered {

    private static final List<String> PUBLIC_ROUTES = List.of(
            "/admin/invitations/validate/",
            "/admin/register"
    );

    private final SessionStore sessionStore;
    private final AuthClient authClient;
    private final SecretKey signingKey;
    private final String cookieName;
    private final boolean cookieSecure;

    public SessionAuthFilter(SessionStore sessionStore,
                              AuthClient authClient,
                              @Value("${jwt.secret}") String jwtSecret,
                              @Value("${planeo.session.cookie-name}") String cookieName,
                              @Value("${planeo.session.cookie-secure}") boolean cookieSecure) {
        this.sessionStore = sessionStore;
        this.authClient = authClient;
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.cookieName = cookieName;
        this.cookieSecure = cookieSecure;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (PUBLIC_ROUTES.stream().anyMatch(path::startsWith)) {
            return chain.filter(stripIdentityHeaders(exchange));
        }

        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(cookieName);
        if (cookie == null) {
            return unauthorized(exchange);
        }

        String sessionId = cookie.getValue();

        return sessionStore.find(sessionId)
                .flatMap(session -> withValidAccessToken(sessionId, session))
                .flatMap(session -> {
                    if (path.startsWith("/admin") && !"ADMIN".equals(session.role())) {
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    }
                    return chain.filter(injectIdentityHeaders(exchange, session));
                })
                .switchIfEmpty(Mono.defer(() -> expireCookieAndReject(exchange, sessionId)));
    }

    private Mono<SessionData> withValidAccessToken(String sessionId, SessionData session) {
        if (session.accessTokenExpiresAt().isAfter(Instant.now().plusSeconds(5))) {
            // Touch the session so activity slides its Redis TTL forward.
            return sessionStore.save(sessionId, session).thenReturn(session);
        }

        return authClient.refresh(session.refreshToken())
                .flatMap(tokens -> {
                    Claims claims = parseClaims(tokens.accessToken());
                    SessionData refreshed = new SessionData(
                            session.username(), session.role(),
                            tokens.accessToken(), tokens.refreshToken(),
                            claims.getExpiration().toInstant());
                    return sessionStore.save(sessionId, refreshed).thenReturn(refreshed);
                })
                .onErrorResume(ex -> sessionStore.delete(sessionId).then(Mono.empty()));
    }

    private ServerWebExchange injectIdentityHeaders(ServerWebExchange exchange, SessionData session) {
        return exchange.mutate()
                .request(r -> r.headers(headers -> {
                    stripIdentityHeaders(headers);
                    headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + session.accessToken());
                    headers.set("X-Auth-Username", session.username());
                    headers.set("X-Auth-Role", session.role());
                }))
                .build();
    }

    private ServerWebExchange stripIdentityHeaders(ServerWebExchange exchange) {
        return exchange.mutate()
                .request(r -> r.headers(this::stripIdentityHeaders))
                .build();
    }

    private void stripIdentityHeaders(HttpHeaders headers) {
        headers.remove(HttpHeaders.AUTHORIZATION);
        headers.remove("X-Auth-Username");
        headers.remove("X-Auth-Role");
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> expireCookieAndReject(ServerWebExchange exchange, String sessionId) {
        ResponseCookie expired = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
        exchange.getResponse().addCookie(expired);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
