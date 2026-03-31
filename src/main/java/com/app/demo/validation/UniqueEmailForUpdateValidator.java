package com.app.demo.validation;

import com.app.demo.dto.request.UserUpdateDto;
import com.app.demo.repository.UserRepository;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UniqueEmailForUpdateValidator
        implements ConstraintValidator<UniqueEmailForUpdate, UserUpdateDto> {

    @Autowired
    private UserRepository userRepository;

    @Override
    public boolean isValid(UserUpdateDto dto, ConstraintValidatorContext context) {

        if (dto.getEmail() == null || dto.getEmail().isEmpty()) {
            return true;
        }

        boolean isExist = userRepository.existsByEmailAndIdNot(
                dto.getEmail(),
                dto.getId()
        );

        if (isExist) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Email already exists")
                    .addPropertyNode("email")
                    .addConstraintViolation();
        }

        return !isExist;
    }
}