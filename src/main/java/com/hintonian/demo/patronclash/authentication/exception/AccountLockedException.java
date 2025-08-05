package com.hintonian.demo.patronclash.authentication.exception;

public class AccountLockedException extends AuthenticationException  {
    public AccountLockedException(String message) {
        super(message);
    }
}
