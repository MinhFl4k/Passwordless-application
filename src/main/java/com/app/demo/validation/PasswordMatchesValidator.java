package com.app.demo.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.BeanWrapperImpl;

public class PasswordMatchesValidator
        implements ConstraintValidator<PasswordMatches, Object> {

    private String firstFieldName;
    private String secondFieldName;

    @Override
    public void initialize(PasswordMatches constraintAnnotation) {
        this.firstFieldName = constraintAnnotation.first();
        this.secondFieldName = constraintAnnotation.second();
    }

    @Override
    public boolean isValid(Object object,
                           ConstraintValidatorContext context) {

        try {
            Object firstValue = new BeanWrapperImpl(object).getPropertyValue(firstFieldName);
            Object secondValue = new BeanWrapperImpl(object).getPropertyValue(secondFieldName);

            if (firstValue == null || secondValue == null) {
                return true;
            }

            boolean isValid = firstValue.equals(secondValue);

            if (!isValid) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Passwords do not match")
                        .addPropertyNode("confirmPassword")
                        .addConstraintViolation();
            }

            return isValid;
        } catch (Exception e) {
            return false;
        }
    }
}