package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegistrationRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 30 characters")
        String username,
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,
        @NotBlank(message = "Password is required")
        @Size(min = 15, max = 64, message = "Password must be between 15 and 64 characters") //NIST-aligned
        String password,
        @NotBlank(message = "Password confirmation is required")
        String passwordConfirmation,
        String firstName,
        String lastName,
        String phoneNumber,
        boolean agreeToTerms) {

        public boolean isPasswordMatching() {
                return password != null && password.equals(passwordConfirmation);
        }
}
