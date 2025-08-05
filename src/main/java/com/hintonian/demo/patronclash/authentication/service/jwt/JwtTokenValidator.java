package com.hintonian.demo.patronclash.authentication.service.jwt;

import com.hintonian.demo.patronclash.authentication.config.JwtConfiguration;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

@Slf4j
@Service
public class JwtTokenValidator {

    private final JwtConfiguration jwtConfiguration;
    private final JwtClaimsExtractor claimsExtractor;

    public JwtTokenValidator(JwtConfiguration jwtConfiguration, JwtClaimsExtractor claimsExtractor) {
        this.jwtConfiguration = jwtConfiguration;
        this.claimsExtractor = claimsExtractor;
    }

    /**
     * Check if the JWT token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            final Date expiration = claimsExtractor.getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (JwtException e) {
            log.error("Error checking token expiration: {}", e.getMessage(), e);
            return true;
        }
    }

    /**
     * Validate JWT token
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(jwtConfiguration.getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired", e);
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty", e);
        } catch (JwtException e) {
            log.error("JWT token validation error", e);
        }
        return false;
    }

    /**
     * Validate JWT token against email
     */
    public boolean validateToken(String token, String username) {
        final String tokenUsername = claimsExtractor.getUsernameFromToken(token);
        return (username.equals(tokenUsername) && !isTokenExpired(token));
    }

    /**
     * Check if the token is a refresh token
     */
    public boolean isRefreshToken(String token) {
        try {
            String tokenType = claimsExtractor.getTokenTypeFromToken(token);
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }
}
