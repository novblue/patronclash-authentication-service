package com.hintonian.demo.patronclash.authentication.service.jwt;

import com.hintonian.demo.patronclash.authentication.config.JwtConfiguration;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
public class JwtClaimsExtractor {

    private final JwtConfiguration jwtConfiguration;

    public JwtClaimsExtractor(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    /**
     * Extract email from JWT token
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extract user ID from a JWT token
     */
    public String getUserIdFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("userId", String.class);
    }

    /**
     * Extract roles from a JWT token
     */
    public Set<String> getRolesFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        Object rolesObject = claims.get("roles"); // Get as Object

        if (rolesObject instanceof List<?> rolesList) { // Check if it's a List
            // Cast to List with wildcard
            return rolesList.stream()
                    .filter(String.class::isInstance) // Filter to ensure elements are Strings
                    .map(String.class::cast)          // Cast each element to String
                    .collect(Collectors.toSet());
        }
        // If the "roles" claim is missing or not a List, return an empty set or throw an exception
        log.warn("JWT did not contain 'roles' claim as a List of Strings for token subject: {}", claims.getSubject());
        return Collections.emptySet();
    }

    /**
     * Extract a token type from a JWT token
     */
    public String getTokenTypeFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("type", String.class);
    }

    /**
     * Extract expiration date from the JWT token
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extract expiration as Instant from a JWT token
     */
    public Instant getExpirationFromToken(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.toInstant();
    }

    /**
     * Get remaining time until token expiration in milliseconds
     */
    public long getRemainingExpirationTime(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.getTime() - System.currentTimeMillis();
        } catch (JwtException e) {
            return 0;
        }
    }

    /**
     * Extract specific claim from a JWT token
     */
    public <T> T getClaimFromToken(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from a JWT token
     */
    public Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(jwtConfiguration.getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            log.error("Failed to parse JWT token: {}", e.getMessage(), e);
            throw e;
        }
    }
}
