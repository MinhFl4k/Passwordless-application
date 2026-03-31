package com.app.demo.enums;

public enum AuthProvider {
    LOCAL,
    GOOGLE,
    GITHUB,
    FACEBOOK;

    public static AuthProvider from(String registrationId) {
        return AuthProvider.valueOf(registrationId.toUpperCase());
    }
}
