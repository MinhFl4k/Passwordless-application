package com.app.demo.enums;

import lombok.Getter;

@Getter
public enum OtpStatus {
    VALID("Valid OTP"),
    INVALID("Invalid OTP"),
    EXPIRED("OTP has expired"),
    USED("OTP has already been used"),
    NOT_FOUND("OTP not found"),
    NOT_CONFIGURE("OTP is not configured for this user");

    private final String message;

    OtpStatus(String message) {
        this.message = message;
    }

}
