package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record SessionRevocationRequest(
        @NotNull(message = "Session ID cannot be null")
        UUID sessionId
) {
}
