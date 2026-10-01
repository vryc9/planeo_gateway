package com.planeo.planeo_gateway.controller;

import com.planeo.planeo_gateway.domain.SessionData;
import com.planeo.planeo_gateway.infrastructure.auth.AuthClient;
import com.planeo.planeo_gateway.infrastructure.redis.SessionStore;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthControllerReauthTest {

    private final AuthClient authClient = mock(AuthClient.class);
    private final SessionStore sessionStore = mock(SessionStore.class);
    private final WebTestClient client = WebTestClient.bindToController(new AuthController(
            authClient, sessionStore, "votre_secret_tres_long_au_moins_256_bits_pour_hs256",
            "PLANEO_SID", 3600, false)).build();

    private final SessionData session = new SessionData("alice", "USER", "a", "r", Instant.now().plusSeconds(60));

    @Test
    void routeExistsAndRejectsRequestsWithoutSession() {
        client.post().uri("/auth/reauth").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"password\":\"x\"}")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void stampsSessionOnCorrectPasswordForAnyRole() {
        when(sessionStore.find("sid")).thenReturn(Mono.just(session));
        when(authClient.login("alice", "secret")).thenReturn(Mono.just(new AuthClient.TokenPair("a", "r")));
        when(sessionStore.save(eq("sid"), any())).thenReturn(Mono.just(true));

        client.post().uri("/auth/reauth").cookie("PLANEO_SID", "sid").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"password\":\"secret\"}")
                .exchange().expectStatus().isNoContent();

        verify(sessionStore).save(eq("sid"), any());
    }

    @Test
    void rejectsWrongPasswordWithoutTouchingSession() {
        when(sessionStore.find("sid")).thenReturn(Mono.just(session));
        when(authClient.login("alice", "bad")).thenReturn(Mono.error(new RuntimeException("401")));

        client.post().uri("/auth/reauth").cookie("PLANEO_SID", "sid").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"password\":\"bad\"}")
                .exchange().expectStatus().isUnauthorized();
    }
}
