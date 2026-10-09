package com.augustopugliano.cypher.config;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.*;

@Component
@Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE)
public class RequestBoundsFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        response.setHeader("Cache-Control", "no-store");
        if (!"POST".equals(request.getMethod())) {
            chain.doFilter(request, response); return;
        }
        if (request.getContentLengthLong() > 16384) { response.setStatus(413); return; }
        var collected = new ByteArrayOutputStream();
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
        byte[] buffer = new byte[1024];
        try {
            while (collected.size() <= 16384) {
                int count = request.getInputStream().read(buffer, 0, Math.min(buffer.length, 16385 - collected.size()));
                if (System.nanoTime() >= deadline) { response.setStatus(408); return; }
                if (count < 0) break;
                collected.write(buffer, 0, count);
            }
        } catch (IOException e) { response.setStatus(408); return; }
        byte[] body = collected.toByteArray();
        if (body.length > 16384) { response.setStatus(413); return; }
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override public ServletInputStream getInputStream() {
                var input = new ByteArrayInputStream(body);
                return new ServletInputStream() {
                    public int read() { return input.read(); }
                    public boolean isFinished() { return input.available() == 0; }
                    public boolean isReady() { return true; }
                    public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException("Synchronous MVC input"); }
                };
            }
            @Override public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(getInputStream(), java.nio.charset.StandardCharsets.UTF_8)); }
        }, response);
    }
}
