package com.planeo.planeo_gateway.domain;

import java.time.Instant;

public record SessionData(
        String username,
        String role,
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt
) {
}
