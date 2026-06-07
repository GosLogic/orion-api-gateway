package com.goslogic.orion.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Global filter que aplica autenticación JWT en el API Gateway.
 *
 * Rutas públicas (allowlist): no se valida el token.
 * Rutas protegidas: se exige Bearer JWT válido firmado con el secreto HMAC compartido con el IAM.
 *
 * Si el token es válido, inyecta los headers de identidad para los servicios downstream:
 *   X-User-Id      → claims.subject (users.id)
 *   X-Tenant-Id    → claims.tenant_id (externalId — autoritativo, reemplaza el header del cliente)
 *   X-Driver-Id    → claims.driver_id (solo si rol DRIVER)
 *   X-Roles        → lista de roles separada por comas
 *   X-User-Email   → claims.email
 */
@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationGlobalFilter.class);

    private static final List<String> PUBLIC_PATHS = List.of(
            "/v1/auth/",
            "/v3/api-docs",
            "/swagger-ui",
            "/actuator/health",
            "/actuator/info"
    );

    private final SecretKey signingKey;

    public JwtAuthenticationGlobalFilter(JwtProperties props) {
        this.signingKey = Keys.hmacShaKeyFor(
                props.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isPublic(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange, "Missing or malformed Authorization header");
        }

        String token = authHeader.substring(7);
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT validation failed for path {}: {}", path, e.getMessage());
            return unauthorized(exchange, "Invalid or expired token");
        }

        // Construir request mutado con los headers de identidad inyectados
        var mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id",    claims.getSubject())
                .header("X-Tenant-Id",  claims.get("tenant_id", String.class))
                .header("X-User-Email", claims.get("email", String.class))
                .header("X-Roles",      buildRolesHeader(claims))
                .build();

        String driverId = claims.get("driver_id", String.class);
        if (driverId != null) {
            mutatedRequest = mutatedRequest.mutate()
                    .header("X-Driver-Id", driverId)
                    .build();
        }

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private boolean isPublic(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    @SuppressWarnings("unchecked")
    private String buildRolesHeader(Claims claims) {
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof List<?> rolesList) {
            return String.join(",", (List<String>) rolesList);
        }
        return "";
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        var body = String.format(
                "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"%s\"}", message);
        var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
