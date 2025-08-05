package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.NotBlank;

public record EmailVerificationRequest(
        @NotBlank(message = "Verification code is required")
        String verificationCode
) {
}
