package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
        @NotBlank(message = "Current password is required")
        String currentPassword,

        @NotBlank(message = "New password is required")
        @Size(min = 15, max = 64, message = "Password must be between 15 and 64 characters")  // NIST-aligned
        String newPassword,

        @NotBlank(message = "Password confirmation is required")
        String confirmPassword
){

    // Simple, stateless utility method
    public boolean isPasswordMatching() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }

}
