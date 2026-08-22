package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.RegisterRequest;
import com.augustopugliano.cypher.exception.UserAlreadyExistsException;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.UserRepository;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
        // Using default Argon2 parameters recommended by Spring Security
        this.passwordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Transactional
    public void register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("El usuario con email " + request.getEmail() + " ya existe");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        // role is "USER" by default and createdAt is set automatically by JPA

        userRepository.save(user);
    }
}
