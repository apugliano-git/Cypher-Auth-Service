package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.AnomalyResult;
import com.augustopugliano.cypher.dto.GeoLocation;
import com.augustopugliano.cypher.model.LoginAuditLog;
import com.augustopugliano.cypher.repository.LoginAuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class AnomalyDetectionService {

    private final LoginAuditLogRepository loginAuditLogRepository;
    private final GeoLocationService geoLocationService;
    private final double maxSpeedKmh;

    public AnomalyDetectionService(
            LoginAuditLogRepository loginAuditLogRepository,
            GeoLocationService geoLocationService,
            @Value("${cypher.anomaly.max-speed-kmh:900}") double maxSpeedKmh) {
        this.loginAuditLogRepository = loginAuditLogRepository;
        this.geoLocationService = geoLocationService;
        this.maxSpeedKmh = maxSpeedKmh;
    }

    public AnomalyResult evaluate(UUID userId, String currentIp) {
        if (userId == null || currentIp == null) {
            return new AnomalyResult(false, null, null, 0, 0);
        }

        GeoLocation currentGeo = geoLocationService.resolve(currentIp);
        if (currentGeo == null) {
            return new AnomalyResult(false, null, null, 0, 0);
        }

        Optional<LoginAuditLog> prevLoginOpt = loginAuditLogRepository.findFirstByUserIdAndSuccessTrueOrderByCreatedAtDesc(userId);
        if (prevLoginOpt.isEmpty()) {
            return new AnomalyResult(false, null, currentGeo, 0, 0);
        }

        LoginAuditLog prevLogin = prevLoginOpt.get();
        GeoLocation prevGeo = geoLocationService.resolve(prevLogin.getIpAddress());
        
        if (prevGeo == null) {
            return new AnomalyResult(false, prevGeo, currentGeo, 0, 0);
        }

        double distance = calculateDistance(prevGeo.lat(), prevGeo.lon(), currentGeo.lat(), currentGeo.lon());
        
        LocalDateTime now = LocalDateTime.now();
        Duration duration = Duration.between(prevLogin.getCreatedAt(), now);
        double hours = duration.toMillis() / (1000.0 * 60 * 60);

        if (hours <= 0) {
            hours = 0.001; // Avoid division by zero
        }

        double speedKmh = distance / hours;

        boolean isAnomaly = speedKmh > maxSpeedKmh;

        return new AnomalyResult(isAnomaly, prevGeo, currentGeo, speedKmh, hours);
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Radius of the earth in km
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
}
