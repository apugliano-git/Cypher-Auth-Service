package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.GeoLocation;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CityResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

@Service
public class GeoLocationService {

    private static final Logger logger = LoggerFactory.getLogger(GeoLocationService.class);
    private DatabaseReader dbReader;
    private final String dbPath;

    public GeoLocationService(@org.springframework.beans.factory.annotation.Value("${cypher.geoip.db-path}") String dbPath) {
        this.dbPath = dbPath;
    }

    @PostConstruct
    public void init() {
        try {
            File database = new File(dbPath);
            if (database.exists()) {
                dbReader = new DatabaseReader.Builder(database).build();
            } else {
                logger.error("GeoIP database not found at {}", dbPath);
            }
        } catch (IOException e) {
            logger.error("Error initializing GeoIP database reader", e);
        }
    }

    @PreDestroy
    public void cleanup() {
        if (dbReader != null) {
            try {
                dbReader.close();
            } catch (IOException e) {
                logger.error("Error closing GeoIP database reader", e);
            }
        }
    }

    public GeoLocation resolve(String ipAddress) {
        if (dbReader == null || ipAddress == null) {
            return null;
        }

        if (ipAddress.startsWith("127.") || ipAddress.equals("::1") || 
            ipAddress.startsWith("192.168.") || ipAddress.startsWith("10.") || ipAddress.startsWith("0:0:0:0:0:0:0:1")) {
            return null;
        }

        try {
            InetAddress ipAddressObj = InetAddress.getByName(ipAddress);
            CityResponse response = dbReader.city(ipAddressObj);

            Double lat = response.getLocation().getLatitude();
            Double lon = response.getLocation().getLongitude();
            String city = response.getCity().getName();
            String country = response.getCountry().getName();

            if (lat != null && lon != null) {
                return new GeoLocation(lat, lon, city != null ? city : "Unknown", country != null ? country : "Unknown");
            }

        } catch (AddressNotFoundException e) {
            return null;
        } catch (Exception e) {
            logger.error("Error resolving IP address: {}", ipAddress, e);
        }

        return null;
    }
}
