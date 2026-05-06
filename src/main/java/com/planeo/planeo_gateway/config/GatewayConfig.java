package com.planeo.planeo_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Value("${planeo.auth.url}")
    private String authUrl;

    @Value("${planeo.back.url}")
    private String backUrl;

    @Value("${planeo.admin.url}")
    private String adminUrl;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Routes vers planeo_auth
                .route("planeo-auth", r -> r
                        .path("/auth/**")
                        .uri(authUrl))
                // Routes vers planeo_back
                .route("planeo-back", r -> r
                        .path("/api/**")
                        .uri(backUrl))
                .route("planeo-admin", r -> r
                        .path("/admin/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri(adminUrl))
                .build();
    }
}