package com.markup.authservice.service;

import com.markup.authservice.dto.JwtResponse;
import com.markup.authservice.dto.LoginRequest;
import com.markup.authservice.dto.LoginResponse;
import com.markup.authservice.dto.RegisterRequest;
import com.markup.authservice.entity.User;
import com.markup.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    // ========================= REGISTER =========================

    public JwtResponse register(RegisterRequest request) {

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        if (userRepository.existsByIdentification(request.getIdentification())) {
            throw new RuntimeException("La identificación ya está registrada.");
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setIdentification(request.getIdentification());
        user.setProvince(request.getProvince());
        user.setCity(request.getCity());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setAmount(request.getAmount());
        user.setRole(request.getRole());
        user.setActive(true);
        user.setRegistrationDate(LocalDateTime.now());
        user.setRequestType(request.getRequestType());

        userRepository.save(user);

        String token = jwtService.generateToken(user);

        return JwtResponse.builder()
                .token(token)
                .message("Usuario registrado exitosamente")
                .build();
    }


    // ========================= LOGIN =========================

    public LoginResponse login(LoginRequest request) {

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = (User) auth.getPrincipal();

        String token = jwtService.generateToken(user);

        LoginResponse response = new LoginResponse();
        response.setToken(token);

        LoginResponse.UserData userData = new LoginResponse.UserData();
        userData.setId(user.getId());
        userData.setEmail(user.getEmail());
        userData.setName(user.getFirstName() + " " + user.getLastName());
        userData.setRole(user.getRole().name().toLowerCase());

        response.setUser(userData);

        return response;
    }
}
