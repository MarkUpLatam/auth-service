package com.markup.authservice.controller;

import com.markup.authservice.dto.JwtResponse;
import com.markup.authservice.dto.LoginRequest;
import com.markup.authservice.dto.RegisterRequest;
import com.markup.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<JwtResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/emails")
    public ResponseEntity<List<String>> getAllEmails() {
        return ResponseEntity.ok(authService.getAllUserEmails());
    }





}
