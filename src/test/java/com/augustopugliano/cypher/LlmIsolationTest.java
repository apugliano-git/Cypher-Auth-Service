package com.augustopugliano.cypher;

import com.augustopugliano.cypher.service.LlmExplanationService;
import com.augustopugliano.cypher.dto.*;
import com.augustopugliano.cypher.repository.LoginAuditLogRepository;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;

class LlmIsolationTest {
    @Test void noApiKeyMeansNoOutboundCall() throws Exception {
        var calls = new AtomicInteger();
        var server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> { calls.incrementAndGet(); byte[] bytes = "{}".getBytes(); exchange.sendResponseHeaders(200, bytes.length); exchange.getResponseBody().write(bytes); exchange.close(); });
        server.start();
        try {
            var repo = org.mockito.Mockito.mock(LoginAuditLogRepository.class);
            var service = new LlmExplanationService("", true, "http://127.0.0.1:" + server.getAddress().getPort(), repo);
            var geo = new GeoLocation(1, 2, "City", "Country");
            service.explainAnomalyAsync(1L, new AnomalyResult(true, geo, geo, 1000, 1));
            assertThat(calls.get()).isZero();
            org.mockito.Mockito.verifyNoInteractions(repo);
        } finally { server.stop(0); }
    }
    @Test void localFailuresMalformedLargeAndSlowResponsesAreContained() throws Exception {
        for (String mode : java.util.List.of("500", "429", "malformed", "large", "slow", "valid")) {
            var server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                if (mode.equals("slow")) { try { Thread.sleep(3500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
                byte[] bytes = (mode.equals("large") ? "x".repeat(17000) : mode.equals("valid") ? "{\"content\":[{\"text\":\"Synthetic explanation\"}]}" : "invalid-json").getBytes();
                try { exchange.sendResponseHeaders(mode.equals("500") ? 500 : mode.equals("429") ? 429 : 200, bytes.length); exchange.getResponseBody().write(bytes); } finally { exchange.close(); }
            }); server.start();
            try {
                var repo = org.mockito.Mockito.mock(LoginAuditLogRepository.class);
                var log = new com.augustopugliano.cypher.model.LoginAuditLog();
                org.mockito.Mockito.when(repo.findById(1L)).thenReturn(java.util.Optional.of(log));
                var service = new LlmExplanationService("synthetic-key", true, "http://127.0.0.1:" + server.getAddress().getPort(), repo);
                var geo = new GeoLocation(1, 2, "City", "Country");
                long before = System.nanoTime();
                service.explainAnomalyAsync(1L, new AnomalyResult(true, geo, geo, 1000, 1));
                assertThat(java.time.Duration.ofNanos(System.nanoTime()-before)).isLessThan(java.time.Duration.ofSeconds(4));
                assertThat(log.getAnomalyExplanation()).isEqualTo(mode.equals("valid") ? "Synthetic explanation" : null);
            } finally { server.stop(0); }
        }
    }
    @Test void explanationExecutorHasBoundedCapacity() throws Exception {
        var executor = new com.augustopugliano.cypher.config.ExplanationConfig().explanationExecutor();
        executor.initialize(); var release = new java.util.concurrent.CountDownLatch(1);
        try {
            Runnable task = () -> { try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } };
            for (int i = 0; i < 18; i++) executor.execute(task);
            assertThatThrownBy(() -> executor.execute(task)).isInstanceOf(org.springframework.core.task.TaskRejectedException.class);
            assertThat(executor.getThreadPoolExecutor().getQueue()).hasSize(16);
        } finally { release.countDown(); executor.shutdown(); }
    }

    @Test void tricklingResponseHasTotalDeadline() throws Exception {
        var server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var worker = java.util.concurrent.Executors.newSingleThreadExecutor(); server.setExecutor(worker);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes(); exchange.sendResponseHeaders(200,0);
            try {
                for (int i=0;i<100;i++) { exchange.getResponseBody().write('x'); exchange.getResponseBody().flush(); Thread.sleep(200); }
            } catch (Exception ignored) { } finally { exchange.close(); }
        }); server.start();
        try {
            var repo = org.mockito.Mockito.mock(LoginAuditLogRepository.class);
            var service = new LlmExplanationService("synthetic-key", true, "http://127.0.0.1:"+server.getAddress().getPort(),repo);
            var geo = new GeoLocation(1,2,"City","Country");
            long before=System.nanoTime(); service.explainAnomalyAsync(1L,new AnomalyResult(true,geo,geo,1000,1));
            assertThat(java.time.Duration.ofNanos(System.nanoTime()-before)).isLessThan(java.time.Duration.ofSeconds(7));
            org.mockito.Mockito.verifyNoInteractions(repo);
        } finally { server.stop(0); worker.shutdownNow(); }
    }

}
