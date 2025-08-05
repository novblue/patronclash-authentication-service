package com.hintonian.demo.patronclash.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min=15, max=64) String password,
        boolean rememberMe,
        String deviceInfo) {}
