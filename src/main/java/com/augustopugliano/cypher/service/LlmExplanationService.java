package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.AnomalyResult;
import com.augustopugliano.cypher.repository.LoginAuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class LlmExplanationService {
    private final java.net.http.HttpClient client;
    private final java.net.URI endpoint;
    private final String apiKey;
    private final LoginAuditLogRepository repository;
    private final boolean enabled;

    public LlmExplanationService(@Value("${cypher.anthropic.api-key:}") String apiKey,
            @Value("${cypher.anthropic.enabled:false}") boolean enabled,
            @Value("${cypher.anthropic.url:https://api.anthropic.com/v1/messages}") String url,
            LoginAuditLogRepository repository) {
        this.enabled = enabled && !apiKey.isBlank();
        this.repository = repository;
        this.apiKey = apiKey; this.endpoint = java.net.URI.create(url);
        this.client = this.enabled ? java.net.http.HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(2))
                .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build() : null;
    }

    @Async("explanationExecutor")
    public void explainAnomalyAsync(Long auditLogId, AnomalyResult anomaly) {
        if (!enabled || anomaly == null || !anomaly.isAnomaly() || anomaly.prevGeo() == null || anomaly.currGeo() == null) return;
        // Only countries and coarse travel estimates leave the service; no identity, IP or tokens.
        String prompt = String.format(Locale.ROOT, "Explain suspicious travel from %s to %s in %.2f hours at about %.0f km/h in 2 sentences.",
                anomaly.prevGeo().country(), anomaly.currGeo().country(), anomaly.hours(), Math.round(anomaly.speedKmh() / 100) * 100.0);
        Map<String,Object> body = Map.of("model", "claude-3-haiku-20240307", "max_tokens", 150,
                "messages", List.of(Map.of("role", "user", "content", prompt)));
        java.util.concurrent.CompletableFuture<java.net.http.HttpResponse<byte[]>> pending = null;
        try {
            var mapper = new tools.jackson.databind.json.JsonMapper();
            var request = java.net.http.HttpRequest.newBuilder(endpoint).timeout(java.time.Duration.ofSeconds(5))
                    .header("x-api-key", apiKey).header("anthropic-version", "2023-06-01").header("Content-Type", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))).build();
            pending = client.sendAsync(request, response -> boundedBody());
            var response = pending.get(5, java.util.concurrent.TimeUnit.SECONDS);
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw new java.io.IOException("LLM unavailable");
            var parsed = mapper.readValue(response.body(), Map.class);
            if (!(parsed.get("content") instanceof List<?> content) || content.isEmpty()
                    || !(content.getFirst() instanceof Map<?,?> item) || !(item.get("text") instanceof String text)
                    || text.isBlank()) throw new java.io.IOException("Invalid LLM response");
            String explanation = text.substring(0, Math.min(text.length(), 2000));
            repository.findById(auditLogId).ifPresent(log -> { log.setAnomalyExplanation(explanation); repository.save(log); });
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            org.slf4j.LoggerFactory.getLogger(LlmExplanationService.class).warn("Optional explanation unavailable: {}", e.getClass().getSimpleName());
        } finally {
            if (pending != null && !pending.isDone()) pending.cancel(true);
        }
    }

    private static java.net.http.HttpResponse.BodySubscriber<byte[]> boundedBody() {
        return new java.net.http.HttpResponse.BodySubscriber<>() {
            private final java.util.concurrent.CompletableFuture<byte[]> result = new java.util.concurrent.CompletableFuture<>();
            private final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            private java.util.concurrent.Flow.Subscription subscription;
            public java.util.concurrent.CompletionStage<byte[]> getBody() { return result; }
            public void onSubscribe(java.util.concurrent.Flow.Subscription value) { subscription = value; value.request(1); }
            public void onNext(List<java.nio.ByteBuffer> chunks) {
                for (var chunk : chunks) {
                    if (bytes.size() + chunk.remaining() > 16384) {
                        subscription.cancel(); result.completeExceptionally(new java.io.IOException("LLM response exceeds limit")); return;
                    }
                    byte[] part = new byte[chunk.remaining()]; chunk.get(part); bytes.writeBytes(part);
                }
                subscription.request(1);
            }
            public void onError(Throwable failure) { result.completeExceptionally(failure); }
            public void onComplete() { result.complete(bytes.toByteArray()); }
        };
    }

    @jakarta.annotation.PreDestroy
    public void close() { if (client != null) client.shutdownNow(); }
}
