package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.GeoLocation;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CityResponse;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

@Service
public class GeoLocationService {

    private DatabaseReader dbReader;

    @PostConstruct
    public void init() {
        try {
            File database = new File("secrets/GeoLite2-City.mmdb");
            if (database.exists()) {
                dbReader = new DatabaseReader.Builder(database).build();
            } else {
                System.err.println("GeoLite2-City.mmdb not found in secrets directory!");
            }
        } catch (IOException e) {
            e.printStackTrace();
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
            e.printStackTrace();
        }

        return null;
    }
}
