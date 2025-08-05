package com.hintonian.demo.patronclash.authentication.service.jwt;

import com.hintonian.demo.patronclash.authentication.config.JwtConfiguration;
import com.hintonian.demo.patronclash.authentication.domain.User;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtTokenGenerator {

    private final JwtConfiguration jwtConfiguration;

    public JwtTokenGenerator(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    /**
     * Generate JWT access token from user details
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("roles", user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toList()));

        return createToken(claims, user.getUsername(), jwtConfiguration.getJwtExpirationMs());
    }

    /**
     * Generate a JWT access token from authentication
     */
    public String generateAccessToken(Authentication authentication) {
        String username = authentication.getName();
        Set<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        return createToken(claims, username, jwtConfiguration.getJwtExpirationMs());
    }

    /**
     * Create custom token with specific expiration
     */
    public String createCustomToken(User user, long expirationMs, Map<String, Object> additionalClaims) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());

        if (additionalClaims != null) {
            claims.putAll(additionalClaims);
        }

        return createToken(claims, user.getUsername(), expirationMs);
    }

    /**
     * Create a JWT token with claims and subject
     */
    private String createToken(Map<String, Object> claims, String subject, long expirationMs) {
        Instant issuedAt = Instant.now();

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuer(jwtConfiguration.getJwtIssuer())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(issuedAt.plusMillis(expirationMs)))
                .signWith(jwtConfiguration.getSigningKey())
                .compact();
    }

}
