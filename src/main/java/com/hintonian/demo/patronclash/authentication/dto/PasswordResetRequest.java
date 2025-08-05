package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetRequest(
        @Email(message = "Email should be valid")
        @NotBlank(message = "Email is required")
        String email
) {
}
