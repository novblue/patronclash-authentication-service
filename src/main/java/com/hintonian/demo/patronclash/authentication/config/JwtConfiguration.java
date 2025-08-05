package com.hintonian.demo.patronclash.authentication.config;

import io.jsonwebtoken.security.Keys;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.security.jwt")
public class JwtConfiguration {

    private String jwtSecret;

    private long jwtExpirationMs;

    private long jwtRefreshExpirationMs;

    private String jwtIssuer;

    @Bean
    public SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
