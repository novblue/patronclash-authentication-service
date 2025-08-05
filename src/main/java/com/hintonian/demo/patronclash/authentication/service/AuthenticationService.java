package com.hintonian.demo.patronclash.authentication.service;

import com.hintonian.demo.patronclash.authentication.config.JwtConfiguration;
import com.hintonian.demo.patronclash.authentication.domain.AccountStatus;
import com.hintonian.demo.patronclash.authentication.domain.RefreshToken;
import com.hintonian.demo.patronclash.authentication.domain.User;
import com.hintonian.demo.patronclash.authentication.dto.*;
import com.hintonian.demo.patronclash.authentication.exception.*;
import com.hintonian.demo.patronclash.authentication.repository.RefreshTokenRepository;
import com.hintonian.demo.patronclash.authentication.repository.UserRepository;
import com.hintonian.demo.patronclash.authentication.service.jwt.JwtClaimsExtractor;
import com.hintonian.demo.patronclash.authentication.service.jwt.JwtTokenGenerator;
import com.hintonian.demo.patronclash.authentication.service.jwt.JwtTokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@Transactional
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtClaimsExtractor jwtClaimsExtractor;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final JwtTokenValidator jwtTokenValidator;
    private final JwtConfiguration jwtConfiguration;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;
    private final GeolocationService geolocationService;

    // Constructor Injection for all dependencies
    // @Autowired is optional for a single constructor in Spring 4.3+
    public AuthenticationService(UserRepository userRepository,
                                 RefreshTokenRepository refreshTokenRepository,
                                 JwtTokenGenerator jwtTokenGenerator,
                                 JwtTokenValidator jwtTokenValidator,
                                 JwtClaimsExtractor jwtClaimsExtractor, // if needed
                                 JwtConfiguration jwtConfiguration,
                                 PasswordEncoder passwordEncoder,
                                 RateLimitService rateLimitService,
                                 GeolocationService geolocationService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenGenerator = jwtTokenGenerator;
        this.jwtTokenValidator = jwtTokenValidator;
        this.jwtClaimsExtractor = jwtClaimsExtractor;
        this.jwtConfiguration = jwtConfiguration;
        this.passwordEncoder = passwordEncoder;
        this.rateLimitService = rateLimitService;
        this.geolocationService = geolocationService;
    }

    /**
     * Register a new user
     */
    public AuthenticationResponse register(RegistrationRequest request, HttpServletRequest httpRequest) {
        log.info("Attempting to register new user: {}", request.username());

        validateRegistrationRequest(request);

        // Check geographic restrictions
        String clientIp = getClientIpAddress(httpRequest);
        if (!geolocationService.isLocationAllowed(clientIp)) {
            throw new GeographicRestrictionException("Registration not allowed from your location");
        }

        // Check if user already exists
        if (userRepository.existsByUsername(request.username())) {
            throw new UserAlreadyExistsException("Username already exists");
        }

        if (userRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Create a new user
        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setPhoneNumber(request.phoneNumber());
        user.setLastPasswordChange(Instant.now());

        // Save user
        user = userRepository.save(user);

        log.info("Successfully registered user: {}", user.getUsername());

        // Generate tokens
        String accessToken = jwtTokenGenerator.generateAccessToken(user);
        String refreshTokenStr = generateAndSaveRefreshToken(user, httpRequest);

        return new AuthenticationResponse(
                accessToken,
                refreshTokenStr,
                getJwtExpirationSeconds(accessToken),
                UserInfo.from(user)
        );
    }

    /**
     * Authenticate user and return tokens
     */
    public AuthenticationResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        log.info("Attempting login for user: {}", request.email());

        String clientIp = getClientIpAddress(httpRequest);

        // Check rate limiting
        if (!rateLimitService.isLoginAllowed(clientIp)) {
            throw new AuthenticationException("Too many login attempts. Please try again later.");
        }

        // Check geographic restrictions
        if (!geolocationService.isLocationAllowed(clientIp)) {
            throw new GeographicRestrictionException("Login not allowed from your location");
        }

        // Find user
        Optional<User> userOpt = userRepository.findActiveByEmail(request.email());
        if (userOpt.isEmpty()) {
            rateLimitService.recordFailedLogin(clientIp);
            throw new AuthenticationException("Invalid credentials");
        }

        User user = userOpt.get();

        // Check if the account is locked
        if (isAccountLocked(user)) {
            throw new AccountLockedException("Account is temporarily locked due to multiple failed login attempts");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            handleFailedLogin(user, clientIp);
            throw new AuthenticationException("Invalid credentials");
        }

        // Successful login
        handleSuccessfulLogin(user, clientIp);

        // Generate tokens
        String accessToken = jwtTokenGenerator.generateAccessToken(user);
        String refreshTokenStr = generateAndSaveRefreshToken(user, httpRequest);

        log.info("Successfully authenticated user: {}", user.getUsername());

        return new AuthenticationResponse(
                accessToken,
                refreshTokenStr,
                getJwtExpirationSeconds(accessToken),
                UserInfo.from(user)
        );
    }

    /**
     * Refresh access token using refresh token
     */
    public AuthenticationResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        log.info("Attempting to refresh access token");

        String refreshTokenStr = request.refreshToken();
        UUID refreshTokenId;

        try {
            refreshTokenId = UUID.fromString(refreshTokenStr);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Refresh token is not a valid UUID");
        }

        // Validate refresh token format
        if (!jwtTokenValidator.validateToken(refreshTokenStr) || !jwtTokenValidator.isRefreshToken(refreshTokenStr)) {
            throw new InvalidTokenException("Invalid refresh token format");
        }

        // Find the refresh token in a database
        Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findValidByToken(
                refreshTokenId, Instant.now());

        if (refreshTokenOpt.isEmpty()) {
            throw new InvalidTokenException("Refresh token not found or expired");
        }

        RefreshToken refreshToken = refreshTokenOpt.get();
        User user = refreshToken.getUser();

        // Check if the user is still active
        if (!user.isActive()) {
            throw new AuthenticationException("User account is not active");
        }

        // Update last used timestamp
        refreshToken.markAsUsed();
        refreshTokenRepository.save(refreshToken);

        // Generate a new access token
        String newAccessToken = jwtTokenGenerator.generateAccessToken(user);

        log.info("Successfully refreshed token for user: {}", user.getUsername());

        return new AuthenticationResponse(
                newAccessToken,
                refreshTokenStr, // Return the same refresh token
                getJwtExpirationSeconds(newAccessToken),
                UserInfo.from(user)
        );
    }

    /**
     * Logout user and invalidate the refresh token
     */
    public void logout(String refreshTokenStr, String username) {
        log.info("Logging out user: {}", username);

        if (refreshTokenStr != null) {
            refreshTokenRepository.revokeByToken(UUID.fromString(refreshTokenStr));
        }

        log.info("Successfully logged out user: {}", username);
    }

    /**
     * Logout from all devices
     */
    public void logoutFromAllDevices(String username) {
        log.info("Logging out user from all devices: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            refreshTokenRepository.revokeAllByUser(userOpt.get());
            log.info("Successfully logged out user from all devices: {}", username);
        }
    }

    /**
     * Change user password
     */
    public void changePassword(String username, PasswordChangeRequest request) {
        log.info("Attempting to change password for user: {}", username);

        if (!request.isPasswordMatching()) {
            throw new AuthenticationException("New password and confirmation do not match");
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();

        // Verify the current password
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        // Update password
        String encodedNewPassword = passwordEncoder.encode(request.newPassword());
        userRepository.updatePassword(user.getId(), encodedNewPassword, Instant.now());

        // Revoke all refresh tokens (force re-login on all devices)
        refreshTokenRepository.revokeAllByUser(user);

        log.info("Successfully changed password for user: {}", username);
    }

    /**
     * Reset password (for forgotten password functionality)
     */
    public void resetPassword(String email, String newPassword, String resetToken) {
        log.info("Attempting to reset password for email: {}", email);

        // In a real implementation, you would validate the reset token
        // For now; this is a simplified version

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();

        // Update password
        String encodedNewPassword = passwordEncoder.encode(newPassword);
        userRepository.updatePassword(user.getId(), encodedNewPassword, Instant.now());

        // Revoke all refresh tokens
        refreshTokenRepository.revokeAllByUser(user);

        log.info("Successfully reset password for user: {}", user.getUsername());
    }

    /**
     * Update user profile information
     */
    public UserInfo updateProfile(String username, ProfileUpdateRequest request) {
        log.info("Updating profile for user: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();

        // Update fields if provided
        if (request.firstName() != null) {
            user.setFirstName(request.firstName());
        }
        if (request.lastName() != null) {
            user.setLastName(request.lastName());
        }
        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber());
        }

        user = userRepository.save(user);

        log.info("Successfully updated profile for user: {}", username);
        return UserInfo.from(user);
    }

    /**
     * Verify email address
     */
    public void verifyEmail(String username, String verificationCode) {
        log.info("Verifying email for user: {}", username);

        // In a real implementation, you would validate the verification code
        // For now; this is a simplified version

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setEmailVerified(true);

            // If both email and phone are verified, mark the user as fully verified
            if (user.isPhoneVerified()) {
                user.setIdentityVerified(true);
            }

            userRepository.save(user);
            log.info("Successfully verified email for user: {}", username);
        }
    }

    /**
     * Get user sessions (active refresh tokens)
     */
    @Transactional(readOnly = true)
    public List<SessionInfo> getUserSessions(String username, HttpServletRequest currentRequest) {
        log.info("Getting sessions for user: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();
        List<RefreshToken> activeTokens = refreshTokenRepository.findValidByUser(user, Instant.now());

        String currentIp = getClientIpAddress(currentRequest);
        String currentUserAgent = currentRequest.getHeader(HttpHeaders.USER_AGENT);

        return activeTokens.stream()
                .map(token -> {
                    // Mark the current session based on IP and User-Agent matching
                    boolean isCurrent = token.getIpAddress() != null &&
                            token.getIpAddress().equals(currentIp) &&
                            token.getUserAgent() != null &&
                            token.getUserAgent().equals(currentUserAgent);

                    return new SessionInfo(
                            token.getId(),
                            token.getDeviceInfo(),
                            token.getIpAddress(),
                            token.getCreatedAt(),
                            token.getLastUsedAt(),
                            isCurrent
                    );
                })
                .toList();
    }

    /**
     * Revoke a specific session
     */
    public void revokeSession(String username, String sessionIdStr) {
        log.info("Revoking session {} for user: {}", sessionIdStr, username);

        UUID sessionId;
        try {
            sessionId = UUID.fromString(sessionIdStr);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationException("Invalid session ID format");
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findById(sessionId);

        if (tokenOpt.isPresent() && tokenOpt.get().getUser().getId().equals(user.getId())) {
            RefreshToken token = tokenOpt.get();
            token.setRevoked(true);
            refreshTokenRepository.save(token);

            log.info("Successfully revoked session {} for user: {}", sessionId, username);
        } else {
            throw new AuthenticationException("Session not found or does not belong to user");
        }
    }

    /**
     * Validate registration request
     */
    private void validateRegistrationRequest(RegistrationRequest request) {
        if (!request.isPasswordMatching()) {
            throw new AuthenticationException("Password and confirmation do not match");
        }

        if (!request.agreeToTerms()) {
            throw new AuthenticationException("You must agree to the terms and conditions");
        }

    }

    /**
     * Generate and save refresh token
     */
    private String generateAndSaveRefreshToken(User user, HttpServletRequest request) {
        // Calculate expiration time using your JWT configuration
        Instant expiresAt = Instant.now().plusMillis(jwtConfiguration.getJwtRefreshExpirationMs());

        RefreshToken refreshToken = new RefreshToken(user, expiresAt);
        refreshToken.setIpAddress(getClientIpAddress(request));
        refreshToken.setUserAgent(request.getHeader(HttpHeaders.USER_AGENT));
        refreshToken.setDeviceInfo(extractDeviceInfo(request));

        // Save to database - UUID will be auto-generated
        refreshToken = refreshTokenRepository.save(refreshToken);

        // Return the UUID as string
        return refreshToken.getId().toString();
    }

    /**
     * Handle successful login
     */
    private void handleSuccessfulLogin(User user, String clientIp) {
        rateLimitService.recordSuccessfulLogin(clientIp);

        // Reset failed attempts and unlock account
        user.setFailedLoginAttempts(0);
        user.setLastLogin(Instant.now());

        userRepository.save(user);
    }

    /**
     * Get the client IP address from request
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Extract device information from request
     */
    private String extractDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        if (userAgent == null) {
            return "Unknown Device";
        }

        // Simple device detection (can be enhanced with a proper library)
        if (userAgent.contains("Mobile") || userAgent.contains("Android") || userAgent.contains("iPhone")) {
            return "Mobile Device";
        } else if (userAgent.contains("Chrome")) {
            return "Chrome Browser";
        } else if (userAgent.contains("Firefox")) {
            return "Firefox Browser";
        } else if (userAgent.contains("Safari")) {
            return "Safari Browser";
        } else if (userAgent.contains("Edge")) {
            return "Edge Browser";
        }

        return "Desktop Browser";
    }

    /**
     * Get user by username
     */
    @Transactional(readOnly = true)
    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Get user by email
     */
    @Transactional(readOnly = true)
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Check if user exists
     */
    @Transactional(readOnly = true)
    public boolean userExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Check if email exists
     */
    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * Get user statistics
     */
    @Transactional(readOnly = true)
    public UserStats getUserStats(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        User user = userOpt.get();
        long activeTokens = refreshTokenRepository.countValidTokensByUser(user, Instant.now());

        return new UserStats(
                user.getCreatedAt(),
                user.getLastLogin(),
                user.getFailedLoginAttempts(),
                activeTokens,
                user.isIdentityVerified(),
                user.isEmailVerified(),
                user.isPhoneVerified(),
                user.getLastPasswordChange()
        );
    }

    /**
     * Clean up expired tokens (scheduled task)
     */
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired refresh tokens");
        refreshTokenRepository.deleteExpiredTokens(Instant.now());

        // Also clean up old revoked tokens (older than 30 days)
        Instant cutoffDate = Instant.now().minus(30, ChronoUnit.DAYS);
        refreshTokenRepository.deleteRevokedTokensOlderThan(cutoffDate);
    }

    /**
     * Unlock expired locked accounts (scheduled task)
     */
    public void unlockExpiredAccounts() {
        log.info("Unlocking expired locked accounts");
        // This would be implemented in the repository layer or as a scheduled task
    }

    private boolean isAccountLocked(User user) {
        return Set.of(AccountStatus.BANNED, AccountStatus.SUSPENDED).contains(user.getAccountStatus());
    }
    
    private long getJwtExpirationSeconds(String accessToken) {
        return jwtClaimsExtractor.getRemainingExpirationTime(accessToken) / 1000;
    }
}
