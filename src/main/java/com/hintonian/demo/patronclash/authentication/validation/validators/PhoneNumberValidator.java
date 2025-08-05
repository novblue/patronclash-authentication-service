package com.hintonian.demo.patronclash.authentication.validation.validators;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import com.hintonian.demo.patronclash.authentication.validation.constraints.ValidPhoneNumber;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.BeanWrapperImpl; // Spring utility for property access

public class PhoneNumberValidator implements ConstraintValidator<ValidPhoneNumber, Object> { // Object, not String now

    private String phoneNumberField;
    private String countryCodeField;

    @Override
    public void initialize(ValidPhoneNumber constraintAnnotation) {
        this.phoneNumberField = constraintAnnotation.phoneNumberField();
        this.countryCodeField = constraintAnnotation.countryCodeField();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        if (value == null) {
            return true; // Let @NotNull/@NotBlank handle nulls
        }

        // Use Spring's BeanWrapper to get field values dynamically
        BeanWrapperImpl beanWrapper = new BeanWrapperImpl(value);
        String phoneNumber = (String) beanWrapper.getPropertyValue(phoneNumberField);
        String countryCode = (String) beanWrapper.getPropertyValue(countryCodeField);

        if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
            return true; // Let @NotBlank handle an empty phone number
        }
        if (countryCode == null || countryCode.trim().isEmpty()) {
            // If country code is missing, you can decide to:
            // 1. Return false immediately (recommended if the country is mandatory for phone validation)
            // 2. Try to infer the country code (libphonenumber can do this, but it's less reliable)
            // 3. Let @NotBlank on countryCodeField handle it.
            // For now, let's assume countryCode is mandatory for proper validation.
            return false;
        }

        try {
            PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
            Phonenumber.PhoneNumber parsedNumber = phoneUtil.parse(phoneNumber, countryCode.toUpperCase()); // Ensure uppercase

            boolean isValid = phoneUtil.isValidNumber(parsedNumber);

            if (!isValid) {
                // Optionally add more specific error messages
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(
                                "Phone number is not valid for " + countryCode.toUpperCase())
                        .addPropertyNode(phoneNumberField) // Attach error to the phone number field
                        .addConstraintViolation();
            }

            return isValid;

        } catch (Exception e) {
            // Log the exception if needed, but for validation, just return false
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                            "Could not parse phone number or country code: " + e.getMessage())
                    .addPropertyNode(phoneNumberField)
                    .addConstraintViolation();
            return false;
        }
    }
}
