package com.hintonian.demo.patronclash.authentication.dto;

import java.time.Instant;
import java.util.UUID;

public record SessionInfo(
        UUID id,
        String deviceInfo,
        String ipAddress,
        Instant createdAt,
        Instant lastUsedAt,
        boolean isCurrent
) {
}
