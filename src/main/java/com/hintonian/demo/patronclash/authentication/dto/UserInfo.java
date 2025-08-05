package com.hintonian.demo.patronclash.authentication.dto;

import com.hintonian.demo.patronclash.authentication.domain.Role;
import com.hintonian.demo.patronclash.authentication.domain.User;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserInfo(
        UUID id,
        String username,
        String email,
        String firstName,
        String lastName,
        boolean isEmailVerified,
        boolean isPhoneVerified,
        boolean isIdentityVerified,
        Set<Role> roles,
        Instant lastLogin,
        Instant createdAt
) {

    public static UserInfo from(User user) {
        return new UserInfo(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isEmailVerified(),
                user.isPhoneVerified(),
                user.isIdentityVerified(),
                user.getRoles(),
                user.getLastLogin(),
                user.getCreatedAt()
        );
    }

}
