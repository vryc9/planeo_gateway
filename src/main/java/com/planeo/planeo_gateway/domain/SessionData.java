package com.planeo.planeo_gateway.domain;

import java.time.Instant;

public record SessionData(
        String username,
        String role,
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant reauthenticatedAt
) {
    public SessionData(String username, String role, String accessToken, String refreshToken,
                       Instant accessTokenExpiresAt) {
        this(username, role, accessToken, refreshToken, accessTokenExpiresAt, null);
    }

    public SessionData withReauthenticatedAt(Instant at) {
        return new SessionData(username, role, accessToken, refreshToken, accessTokenExpiresAt, at);
    }

    public SessionData withTokens(String newAccessToken, String newRefreshToken, Instant newExpiresAt) {
        return new SessionData(username, role, newAccessToken, newRefreshToken, newExpiresAt, reauthenticatedAt);
    }
}
