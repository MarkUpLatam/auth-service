package com.markup.authservice.service;

import com.markup.authservice.dto.JwtResponse;
import com.markup.authservice.dto.LoginRequest;
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
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public JwtResponse register(RegisterRequest request) {

        // Verificar si el email ya está registrado
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        // Verificar si la identificación ya existe
        if (userRepository.existsByIdentification(request.getIdentification())) {
            throw new RuntimeException("La identificación ya está registrada.");
        }

        // Crear usuario con todos los campos
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

        // Guardar en la base de datos
        userRepository.save(user);

        // Generar token JWT
        String token = jwtService.generateToken(user);
        return new JwtResponse(token);
    }

    public JwtResponse login(LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        User user = (User) auth.getPrincipal();
        String jwt = jwtService.generateToken(user);
        return new JwtResponse(jwt);
    }

    public List<String> getAllUserEmails() {
        return userRepository.findAll().stream()
                .map(User::getEmail)
                .toList();
    }

}
