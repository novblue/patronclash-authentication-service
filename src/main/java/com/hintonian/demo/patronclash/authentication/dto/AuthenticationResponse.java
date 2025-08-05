package com.hintonian.demo.patronclash.authentication.dto;

public record AuthenticationResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserInfo userInfo
) {
    public AuthenticationResponse(String accessToken, String refreshToken, long expiresIn, UserInfo userInfo) {
        this(accessToken, refreshToken, "Bearer", expiresIn, userInfo);
    }

    public static AuthenticationResponse of(String accessToken, String refreshToken, long expiresIn, UserInfo userInfo) {
        return new AuthenticationResponse(accessToken, refreshToken, expiresIn, userInfo);
    }
}
