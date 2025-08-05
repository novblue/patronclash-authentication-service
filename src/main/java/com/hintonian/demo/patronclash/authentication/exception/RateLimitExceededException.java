package com.hintonian.demo.patronclash.authentication.exception;

public class RateLimitExceededException extends AuthenticationException  {
    public RateLimitExceededException(String message) {
        super(message);
    }
}
