package com.planeo.planeo_gateway.infrastructure.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The gateway is the sole HTTP client of planeo_auth. The browser never talks to it directly.
 */
@Component
public class AuthClient {

    private final WebClient webClient;

    public AuthClient(WebClient.Builder webClientBuilder, @Value("${planeo.auth.url}") String authUrl) {
        this.webClient = webClientBuilder.baseUrl(authUrl).build();
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
    public record TokenPair(String accessToken, String refreshToken) {}

    public Mono<TokenPair> login(String username, String password) {
        return webClient.post()
                .uri("/auth/login")
                .bodyValue(new LoginRequest(username, password))
                .retrieve()
                .bodyToMono(TokenPair.class);
    }

    public Mono<TokenPair> refresh(String refreshToken) {
        return webClient.post()
                .uri("/auth/refresh")
                .bodyValue(new RefreshRequest(refreshToken))
                .retrieve()
                .bodyToMono(TokenPair.class);
    }
}
