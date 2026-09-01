package com.augustopugliano.cypher.controller;

import com.augustopugliano.cypher.dto.LoginRequest;
import com.augustopugliano.cypher.dto.RegisterRequest;
import com.augustopugliano.cypher.dto.RefreshRequest;
import com.augustopugliano.cypher.dto.TokenResponse;
import com.augustopugliano.cypher.dto.UserDto;
import com.augustopugliano.cypher.exception.TokenRefreshException;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.UserRepository;
import com.augustopugliano.cypher.security.AuthenticatedUser;
import com.augustopugliano.cypher.service.JwtService;
import com.augustopugliano.cypher.service.LoginService;
import com.augustopugliano.cypher.service.RefreshTokenService;
import com.augustopugliano.cypher.service.RefreshTokenService.RotationResult;
import com.augustopugliano.cypher.service.RateLimitService;
import com.augustopugliano.cypher.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.beans.factory.annotation.Value;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final LoginService loginService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final RateLimitService rateLimitService;
    private final int maxAttempts;

    public AuthController(UserService userService, 
                          LoginService loginService, 
                          RefreshTokenService refreshTokenService,
                          JwtService jwtService,
                          RateLimitService rateLimitService,
                          @Value("${cypher.rate-limit.max-attempts}") int maxAttempts) {
        this.userService = userService;
        this.loginService = loginService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.rateLimitService = rateLimitService;
        this.maxAttempts = maxAttempts;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        if (rateLimitService.checkAndIncrement("register_attempts:", httpRequest.getRemoteAddr()) > maxAttempts) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
        }
        userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        String ipAddress = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");
        
        TokenResponse response = loginService.performLogin(request, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            RotationResult result = refreshTokenService.processRefresh(request.getRefresh_token());
                
            String newAccessToken = jwtService.generateToken(result.user());
            return ResponseEntity.ok(new TokenResponse(newAccessToken, result.newRawToken(), jwtService.getExpirationSeconds()));
        } catch (TokenRefreshException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getMe() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
        AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
            
        String role = authentication.getAuthorities().stream()
            .findFirst()
            .map(auth -> auth.getAuthority().replace("ROLE_", ""))
            .orElse("USER");
            
        return ResponseEntity.ok(new UserDto(user.id(), user.email(), role));
    }
}
