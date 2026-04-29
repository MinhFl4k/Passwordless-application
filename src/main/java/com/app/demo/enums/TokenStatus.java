package com.app.demo.enums;

import lombok.Getter;

@Getter
public enum TokenStatus {
    VALID("Valid Token"),
    INVALID("Invalid Token"),
    EXPIRED("Token has expired"),
    USED("Token has already been used"),
    NOT_FOUND("Token not found");

    private final String message;

    TokenStatus(String message) {
        this.message = message;
    }
}
