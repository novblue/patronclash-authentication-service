package com.hintonian.demo.patronclash.authentication.validation.constraints;

import com.hintonian.demo.patronclash.authentication.validation.validators.PhoneNumberValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PhoneNumberValidator.class)
@Target({ ElementType.TYPE, ElementType.ANNOTATION_TYPE }) // Apply at class level now!
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPhoneNumber {
    String message() default "Invalid phone number";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    String phoneNumberField() default "phoneNumber"; // Name of the phone number field
    String countryCodeField() default "countryCode"; // Name of the country code field

    // You might also add types of numbers allowed (e.g., MOBILE, FIXED_LINE)
    // Phonenumber.PhoneNumber.CountryCodeSource numberType() default Phonenumber.PhoneNumber.CountryCodeSource.FROM_NUMBER_WITH_PLUS_SIGN;
}
