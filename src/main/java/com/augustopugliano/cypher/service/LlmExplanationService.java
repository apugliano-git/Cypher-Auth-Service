package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.AnomalyResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import java.util.List;
import java.util.Map;

@Service
public class LlmExplanationService {

    private final RestClient restClient;

    public LlmExplanationService(@Value("${cypher.anthropic.api-key:}") String apiKey) {
        this.restClient = RestClient.builder()
                .baseUrl("https://api.anthropic.com/v1/messages")
                .defaultHeader("x-api-key", apiKey)
                .defaultHeader("anthropic-version", "2023-06-01")
                .defaultHeader("content-type", "application/json")
                .build();
    }

    public String explainAnomaly(AnomalyResult anomaly) {
        if (anomaly == null || !anomaly.isAnomaly()) return null;

        String prevLoc = anomaly.prevGeo().city() + ", " + anomaly.prevGeo().country();
        String currLoc = anomaly.currGeo().city() + ", " + anomaly.currGeo().country();
        
        String prompt = String.format("Explica brevemente (2 o 3 oraciones) por qué es sospechoso un inicio de sesión que saltó de %s a %s en %.2f horas a una velocidad estimada de %.2f km/h. Responde en español y de forma directa.",
                prevLoc, currLoc, anomaly.hours(), anomaly.speedKmh());

        Map<String, Object> requestBody = Map.of(
                "model", "claude-3-haiku-20240307",
                "max_tokens", 150,
                "messages", List.of(
                        Map.of("role", "user", "content", prompt)
                )
        );

        try {
            Map response = restClient.post()
                    .body(requestBody)
                    .retrieve()
                    .body(Map.class);

            if (response != null && response.containsKey("content")) {
                List<Map<String, Object>> content = (List<Map<String, Object>>) response.get("content");
                if (!content.isEmpty()) {
                    return (String) content.get(0).get("text");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "No se pudo generar la explicación debido a un error de conexión con el LLM.";
        }

        return "Explicación no disponible.";
    }
}
