package com.augustopugliano.cypher.dto;

public record AnomalyResult(boolean isAnomaly, GeoLocation prevGeo, GeoLocation currGeo, double speedKmh, double hours) {
}
