package com.hintonian.demo.patronclash.authentication.exception;

public class UserAlreadyExistsException extends AuthenticationException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }

}
