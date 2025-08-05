package com.hintonian.demo.patronclash.authentication.dto;

import java.time.Instant;

public record UserStats(
        Instant accountCreated,
        Instant lastLogin,
        int failedLoginAttempts,
        long activeSessions,
        boolean isIdentityVerified,
        boolean isEmailVerified,
        boolean isPhoneVerified,
        Instant lastPasswordChange
) {
}
