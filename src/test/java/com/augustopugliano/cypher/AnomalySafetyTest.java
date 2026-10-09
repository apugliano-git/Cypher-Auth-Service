package com.augustopugliano.cypher;

import com.augustopugliano.cypher.service.*;
import com.augustopugliano.cypher.repository.*;
import com.augustopugliano.cypher.model.*;
import com.augustopugliano.cypher.dto.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

class AnomalySafetyTest {
    @Test void nonPositiveTravelDurationIsUnknownRatherThanFabricatedSpeed() {
        var repo = mock(LoginAuditLogRepository.class); var geo = mock(GeoLocationService.class); UUID id = UUID.randomUUID();
        var previous = new LoginAuditLog(); previous.setIpAddress("198.51.100.1"); previous.setCreatedAt(LocalDateTime.now().plusDays(1));
        when(repo.findFirstByUserIdAndSuccessTrueOrderByCreatedAtDesc(id)).thenReturn(Optional.of(previous));
        when(geo.resolve("198.51.100.1")).thenReturn(new GeoLocation(0,0,"City","Country"));
        when(geo.resolve("198.51.100.2")).thenReturn(new GeoLocation(45,45,"Other","Country"));
        assertThat(new AnomalyDetectionService(repo,geo,900).evaluate(id,"198.51.100.2").isAnomaly()).isFalse();
    }
    @Test void absentOrCorruptGeoDatabaseDegradesToUnknown() throws Exception {
        var path = java.nio.file.Files.createTempFile("synthetic-geo-", ".mmdb"); java.nio.file.Files.writeString(path,"corrupt synthetic data");
        try {
            var service = new GeoLocationService(path.toString()); service.init();
            for (var address : List.of("127.0.0.1","::1","10.0.0.1","fe80::1","localhost","invalid", "2001:db8::1")) assertThat(service.resolve(address)).isNull();
            service.cleanup();
        } finally { java.nio.file.Files.delete(path); }
    }
}
