package com.markup.authservice.service;

import com.markup.authservice.client.NotificationClient;
import com.markup.authservice.dto.*;
import com.markup.authservice.entity.User;
import com.markup.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final NotificationClient notificationClient;


    // ========================= REGISTER =========================

    public JwtResponse register(RegisterRequest request) {

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        if (userRepository.existsByIdentification(request.getIdentification())) {
            throw new RuntimeException("La identificación ya está registrada.");
        }

        String rawPassword = request.getPassword();

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
        log.info("Usuario guardado: {}", user.getEmail());

        String token = jwtService.generateToken(user);
        log.info("Enviando notificación de bienvenida a: {}", user.getEmail());




        try {
            notificationClient.sendNotification(new NotificationRequest(
                    "WELCOME",
                    user.getEmail(),
                    user.getFirstName(),
                    user.getLastName(),
                    rawPassword

            ));
            log.info("Notificación enviada exitosamente");
        } catch (Exception e) {
            log.error("Error al enviar notificación: {}", e.getMessage(), e);

        }

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
