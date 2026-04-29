package com.app.demo.enums;

import lombok.Getter;

@Getter
public enum RoleEnum {
    ROLE_ADMIN("ADMIN"),
    ROLE_MEMBER("MEMBER"),
    ROLE_GUEST("GUEST");

    private final String message;

    RoleEnum(String message) {
        this.message = message;
    }
}
