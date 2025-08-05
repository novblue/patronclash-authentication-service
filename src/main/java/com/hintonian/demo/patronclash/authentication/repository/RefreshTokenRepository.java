package com.hintonian.demo.patronclash.authentication.repository;

import com.hintonian.demo.patronclash.authentication.domain.RefreshToken;
import com.hintonian.demo.patronclash.authentication.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    // Find a valid (non-revoked and non-expired) refresh token
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.id = :tokenId AND rt.isRevoked = false AND rt.expiresAt > :now")
    Optional<RefreshToken> findValidByToken(@Param("tokenId") UUID tokenId, @Param("now") Instant now);

    // Find valid refresh tokens by user ID
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.isRevoked = false AND rt.expiresAt > :now")
    List<RefreshToken> findValidByUser(@Param("user") User user, @Param("now") Instant now);

    // Revoke all refresh tokens for a user
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true WHERE rt.user = :user")
    void revokeAllByUser(@Param("user") User user);

    // Revoke a specific refresh token
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true WHERE rt.id = :tokenId")
    void revokeByToken(@Param("token") UUID tokenId);

    // Update last used timestamp
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.lastUsedAt = :lastUsed WHERE rt.id = :tokenId")
    void updateLastUsed(@Param("token") UUID tokenId, @Param("lastUsed") Instant lastUsed);

    // Delete expired refresh tokens (cleanup)
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    // Delete revoked refresh tokens older than the specified time (cleanup)
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.isRevoked = true AND rt.createdAt < :cutoffDate")
    void deleteRevokedTokensOlderThan(@Param("cutoffDate") Instant cutoffDate);

    // Count valid refresh tokens for a user
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user AND rt.isRevoked = false AND rt.expiresAt > :now")
    long countValidTokensByUser(@Param("user") User user, @Param("now") Instant now);

    // Find valid refresh tokens that will expire soon (for notification purposes)
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.isRevoked = false AND rt.expiresAt BETWEEN :now AND :soonThreshold")
    List<RefreshToken> findValidTokensExpiringSoon(@Param("now") Instant now, @Param("soonThreshold") Instant soonThreshold);
    
}
