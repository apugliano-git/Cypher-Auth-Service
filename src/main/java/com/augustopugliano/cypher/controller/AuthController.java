package com.augustopugliano.cypher.controller;

import com.augustopugliano.cypher.dto.LoginRequest;
import com.augustopugliano.cypher.dto.RegisterRequest;
import com.augustopugliano.cypher.dto.TokenResponse;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.UserRepository;
import com.augustopugliano.cypher.service.JwtService;
import com.augustopugliano.cypher.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final com.augustopugliano.cypher.service.RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, UserRepository userRepository, JwtService jwtService, com.augustopugliano.cypher.service.RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());
        
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = optionalUser.get();
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String accessToken = jwtService.generateToken(user);
        com.augustopugliano.cypher.service.RefreshTokenService.TokenPair pair = refreshTokenService.generateAndSaveRefreshToken(user);
        return ResponseEntity.ok(new TokenResponse(accessToken, pair.rawToken(), 900));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody com.augustopugliano.cypher.dto.RefreshRequest request) {
        try {
            com.augustopugliano.cypher.service.RefreshTokenService.RotationResult result = 
                refreshTokenService.processRefresh(request.getRefresh_token());
                
            String newAccessToken = jwtService.generateToken(result.user());
            return ResponseEntity.ok(new TokenResponse(newAccessToken, result.newRawToken(), 900));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @org.springframework.web.bind.annotation.GetMapping("/me")
    public ResponseEntity<com.augustopugliano.cypher.dto.UserDto> getMe() {
        org.springframework.security.core.Authentication authentication = 
            org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            
        com.augustopugliano.cypher.security.AuthenticatedUser user = 
            (com.augustopugliano.cypher.security.AuthenticatedUser) authentication.getPrincipal();
            
        String role = authentication.getAuthorities().stream()
            .findFirst()
            .map(auth -> auth.getAuthority().replace("ROLE_", ""))
            .orElse("USER");
            
        return ResponseEntity.ok(new com.augustopugliano.cypher.dto.UserDto(user.id(), user.email(), role));
    }
}
