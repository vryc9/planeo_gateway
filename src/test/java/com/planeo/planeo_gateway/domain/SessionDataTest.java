package com.planeo.planeo_gateway.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SessionDataTest {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void sessionsStoredBeforeReauthExistedStillDeserialize() throws Exception {
        String legacyJson = """
                {"username":"alice","role":"USER","accessToken":"a","refreshToken":"r","accessTokenExpiresAt":"2026-10-01T12:00:00Z"}
                """;

        SessionData session = mapper.readValue(legacyJson, SessionData.class);

        assertEquals("alice", session.username());
        assertNull(session.reauthenticatedAt());
    }

    @Test
    void reauthenticationSurvivesTokenRefreshAndRoundTrip() throws Exception {
        Instant at = Instant.parse("2026-10-01T12:00:00Z");
        SessionData session = new SessionData("alice", "USER", "a", "r", at)
                .withReauthenticatedAt(at)
                .withTokens("a2", "r2", at.plusSeconds(60));

        SessionData read = mapper.readValue(mapper.writeValueAsString(session), SessionData.class);

        assertEquals(at, read.reauthenticatedAt());
        assertEquals("a2", read.accessToken());
    }
}
