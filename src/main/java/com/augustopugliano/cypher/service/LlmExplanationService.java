package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.AnomalyResult;
import com.augustopugliano.cypher.model.LoginAuditLog;
import com.augustopugliano.cypher.repository.LoginAuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Service
public class LlmExplanationService {

    private static final Logger logger = LoggerFactory.getLogger(LlmExplanationService.class);
    private final RestClient restClient;
    private final LoginAuditLogRepository loginAuditLogRepository;

    public LlmExplanationService(
            @Value("${cypher.anthropic.api-key:}") String apiKey,
            LoginAuditLogRepository loginAuditLogRepository) {
        this.restClient = RestClient.builder()
                .baseUrl("https://api.anthropic.com/v1/messages")
                .defaultHeader("x-api-key", apiKey)
                .defaultHeader("anthropic-version", "2023-06-01")
                .defaultHeader("content-type", "application/json")
                .build();
        this.loginAuditLogRepository = loginAuditLogRepository;
    }

    @Async
    public void explainAnomalyAsync(Long auditLogId, AnomalyResult anomaly) {
        if (anomaly == null || !anomaly.isAnomaly()) return;

        String prevLoc = anomaly.prevGeo().city() + ", " + anomaly.prevGeo().country();
        String currLoc = anomaly.currGeo().city() + ", " + anomaly.currGeo().country();
        
        String prompt = String.format("Briefly explain (in 2 to 3 sentences) why a login attempt that jumped from %s to %s in %.2f hours at an estimated speed of %.2f km/h is suspicious. Respond in English and be direct.",
                prevLoc, currLoc, anomaly.hours(), anomaly.speedKmh());

        Map<String, Object> requestBody = Map.of(
                "model", "claude-3-haiku-20240307",
                "max_tokens", 150,
                "messages", List.of(
                        Map.of("role", "user", "content", prompt)
                )
        );

        String explanation;
        try {
            Map<String, Object> response = restClient.post()
                    .body(requestBody)
                    .retrieve()
                    .body(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});

            if (response != null && response.containsKey("content")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> content = (List<Map<String, Object>>) response.get("content");
                if (!content.isEmpty()) {
                    explanation = (String) content.get(0).get("text");
                } else {
                    explanation = "Explanation unavailable.";
                }
            } else {
                explanation = "Explanation unavailable.";
            }
        } catch (Exception e) {
            logger.error("Error calling Anthropic API for anomaly explanation", e);
            explanation = "Could not generate explanation due to a connection error with the LLM.";
        }

        String finalExplanation = explanation;
        loginAuditLogRepository.findById(auditLogId).ifPresent(auditLog -> {
            auditLog.setAnomalyExplanation(finalExplanation);
            loginAuditLogRepository.save(auditLog);
        });
    }
}
