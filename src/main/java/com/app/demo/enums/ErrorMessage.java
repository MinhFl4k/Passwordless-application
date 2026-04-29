package com.app.demo.enums;

import lombok.Getter;

@Getter
public enum ErrorMessage {

    EMAIL_REQUIRED("Email is required"),
    EMAIL_EXIST("Email already exists"),

    USER_NOT_FOUND("User not found"),
    USER_ALREADY_VERIFIED("User has already been verified."),

    INVALID_ROLE("Role not found"),
    PASSWORD_NOT_MATCH("Password do not match"),
    ACCOUNT_LOCKED("Your account is temporarily locked due to multiple failed sign-in attempts.");

    private final String message;

    ErrorMessage(String message) {
        this.message = message;
    }
}
