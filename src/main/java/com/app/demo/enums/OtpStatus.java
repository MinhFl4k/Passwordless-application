package com.app.demo.enums;

public enum OtpStatus {
    VALID("Verification successful"),
    INVALID("Invalid OTP"),
    EXPIRED("OTP has expired"),
    USED("OTP has already been used"),
    NOT_FOUND("OTP not found");

    private final String message;

    OtpStatus(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
