package com.hintonian.demo.patronclash.authentication.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private T data;
    private String error;
    private Instant timestamp;

    public ApiResponse() {
        this.timestamp = Instant.now();
    }

    public ApiResponse(boolean success, String message) {
        this();
        this.success = success;
        this.message = message;
    }

    public ApiResponse(boolean success, String message, T data) {
        this(success, message);
        this.data = data;
    }

    // Static factory methods
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    public static <T> ApiResponse<T> success(String message) {
        return new ApiResponse<>(true, message);
    }

    public static <T> ApiResponse<T> error(String message, String error) {
        ApiResponse<T> response = new ApiResponse<>(false, message);
        response.setError(error);
        return response;
    }
}
