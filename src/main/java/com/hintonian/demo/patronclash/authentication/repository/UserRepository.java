package com.hintonian.demo.patronclash.authentication.repository;

import com.hintonian.demo.patronclash.authentication.domain.AccountStatus;
import com.hintonian.demo.patronclash.authentication.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);

    // Find active user only by username
    @Query("SELECT u FROM User u WHERE u.isActive = true AND u.accountStatus = 'ACTIVE' AND u.username == :username")
    Optional<User> findActiveByUsername(String username);

    // Find active user only by email
    @Query("SELECT u FROM User u WHERE u.isActive = true AND u.accountStatus = 'ACTIVE' AND u.email == :email")
    Optional<User> findActiveByEmail(String email);

    // Update failed login attempts
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = :attempts WHERE u.id = :userId")
    void updateFailedLoginAttempts(@Param("userId") UUID userId, @Param("attempts") int attempts);

    // Lock user account
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockedUntil WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") UUID userId, @Param("lockedUntil") Instant lockedUntil);

    // Reset failed attempts and unlock account
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = null WHERE u.id = :userId")
    void resetFailedAttemptsAndUnlock(@Param("userId") UUID userId);

    // Update last login
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") UUID userId, @Param("lastLogin") Instant lastLogin);
    
    // Update password and password change date
    @Modifying
    @Query("UPDATE User u SET u.password = :password, u.lastPasswordChange = :changeDate WHERE u.id = :userId")
    void updatePassword(@Param("userId") UUID userId, @Param("password") String password, @Param("changeDate") Instant changeDate);

    // Find users with expired locked accounts (for cleanup)
    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil < :now")
    Optional<User> findUsersWithExpiredLocks(@Param("now") Instant now);

    // Update email verification status
    @Modifying
    @Query("UPDATE User u SET u.isEmailVerified = :verified WHERE u.id = :userId")
    void updateEmailVerificationStatus(@Param("userId") UUID userId, @Param("verified") boolean verified);

    // Update phone verification status
    @Modifying
    @Query("UPDATE User u SET u.isPhoneVerified = :verified WHERE u.id = :userId")
    void updatePhoneVerificationStatus(@Param("userId") UUID userId, @Param("verified") boolean verified);

    // Update identity verification status
    @Modifying
    @Query("UPDATE User u SET u.isIdentityVerified = :verified WHERE u.id = :userId")
    void updateIdentityVerificationStatus(@Param("userId") UUID userId, @Param("verified") boolean verified);

    // Update account status
    @Modifying
    @Query("UPDATE User u SET u.accountStatus = :status WHERE u.id = :userId")
    void updateAccountStatus(@Param("userId") UUID userId, @Param("status") AccountStatus status);
    
}
