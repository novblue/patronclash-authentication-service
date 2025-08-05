package com.hintonian.demo.patronclash.authentication.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_user_id", columnList = "user_id"),
        @Index(name = "idx_expires_at", columnList = "expires_at"),
        @Index(name = "idx_user_valid", columnList = "user_id, is_revoked, expires_at")
})
@EntityListeners(AuditingEntityListener.class)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id; // This IS the token

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "is_revoked", nullable = false)
    private boolean isRevoked = false;

    @Column(name = "device_info", length = 500)
    private String deviceInfo;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 1000)
    private String userAgent;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    public RefreshToken(User user, Instant expiresAt) {
        this.user = user;
        this.expiresAt = expiresAt;
    }

    public void markAsUsed() {
        this.lastUsedAt = Instant.now();
    }
}
