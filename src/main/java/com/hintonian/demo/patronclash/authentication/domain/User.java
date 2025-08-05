package com.hintonian.demo.patronclash.authentication.domain;

import com.hintonian.demo.patronclash.authentication.validation.constraints.ValidPhoneNumber;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@ValidPhoneNumber
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_email", columnList = "email"),
        @Index(name = "idx_username", columnList = "email")
})
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotBlank
    @Size(min = 3, max = 50)
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank
    @Email
    @Size(max = 100)
    @Column(unique = true, nullable = false)
    private String email;

    @NotBlank
    @Size(min = 8, max = 100)
    @Column(nullable = false)
    private String password;

    @Column(name = "first_name", length = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @NotBlank(message = "Country code is required")
    @Pattern(regexp = "^[A-Z]{2}$", message = "Invalid country code format")
    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    @Column(name = "is_identity_verified", nullable = false)
    private boolean isIdentityVerified = false;

    @Column(name = "is_email_verified", nullable = false)
    private boolean isEmailVerified = false;

    @Column(name = "is_phone_verified", nullable = false)
    private boolean isPhoneVerified = false;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_login")
    private Instant lastLogin;

    @Column(name = "last_password_change")
    private Instant lastPasswordChange;

    @Enumerated(EnumType.STRING)
    @Column(name = "account_status", nullable = false)
    private AccountStatus accountStatus = AccountStatus.ACTIVE;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<Role> roles = new HashSet<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;

    // Constructor with required fields
    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.roles.add(Role.USER);
    }
}
