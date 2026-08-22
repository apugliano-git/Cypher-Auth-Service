package com.augustopugliano.cypher.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF since we are building an API
            .csrf(AbstractHttpConfigurer::disable)
            // Permit all requests for now, as requested, to leave endpoints public
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            
        return http.build();
    }
}
