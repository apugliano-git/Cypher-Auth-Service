package com.augustopugliano.cypher;

import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import com.augustopugliano.cypher.service.*;
import com.augustopugliano.cypher.model.*;
import com.augustopugliano.cypher.repository.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshBoundaryTest {
    @Test void exactExpirationIsInvalidWithoutSkew() {
        Instant now = Instant.parse("2026-10-08T12:00:00Z");
        var repo = mock(RefreshTokenRepository.class);
        var service = new RefreshTokenService(repo, 7, mock(JwtService.class), Clock.fixed(now, ZoneOffset.UTC));
        var token = new RefreshToken(); token.setExpiresAt(now); token.setUser(new User());
        when(repo.findWithLockByTokenHash(service.hashToken("synthetic"))).thenReturn(Optional.of(token));
        assertThatThrownBy(() -> service.processRefresh("synthetic")).isInstanceOf(com.augustopugliano.cypher.exception.TokenRefreshException.class);
        assertThat(token.isRevoked()).isFalse();
    }
}
