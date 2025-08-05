package com.hintonian.demo.patronclash.authentication.dto;

import com.hintonian.demo.patronclash.authentication.validation.constraints.ValidPhoneNumber;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@ValidPhoneNumber
public record ProfileUpdateRequest(
        @NotBlank(message = "First name cannot be blank")
        @Size(min = 1, max = 50, message = "First name must be between 1-50 characters")
        String firstName,
        @NotBlank(message = "Last name cannot be blank")
        @Size(min = 1, max = 50, message = "Last name must be between 1-50 characters")
        String lastName,
        @NotBlank(message = "Phone number is required")
        @Getter // because Spring BeanWrapperImpl doesn't play nice with Java record's getters
        String phoneNumber,
        @NotBlank(message = "Country code is required")
        @Pattern(regexp = "^[A-Z]{2}$", message = "Invalid country code format")
        String countryCode
) {
}
