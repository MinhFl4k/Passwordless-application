package com.app.demo.validation;

import com.app.demo.service.UserService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OldPasswordValidator implements ConstraintValidator<OldPassword, String> {

    private final UserService userService;

    @Override
    public boolean isValid(String oldPassword, ConstraintValidatorContext context) {

        if (oldPassword == null || oldPassword.isBlank()) {
            return true;
        }

        String email = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        return userService.checkOldPassword(email, oldPassword);
    }
}
