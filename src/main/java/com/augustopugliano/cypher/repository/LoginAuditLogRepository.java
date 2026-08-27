package com.augustopugliano.cypher.repository;

import com.augustopugliano.cypher.model.LoginAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface LoginAuditLogRepository extends JpaRepository<LoginAuditLog, Long> {
    Optional<LoginAuditLog> findFirstByUserIdAndSuccessTrueOrderByCreatedAtDesc(UUID userId);
}
