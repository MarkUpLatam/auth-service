package com.markup.authservice.service;

import com.markup.authservice.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    /**
     * Genera un token JWT para un usuario
     * @param user Usuario autenticado
     * @return Token JWT firmado
     */
    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getEmail())                                    // Email como identificador
                .setIssuedAt(new Date())                                        // Fecha de emisión
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // Fecha de expiración
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)           // Firma con HS256
                .compact();
    }

    /**
     * Extrae el email (username) del token
     * @param token JWT token
     * @return Email del usuario
     */
    public String extractUsername(String token) {
        try {
            return parseClaims(token).getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Error al extraer username del token: " + e.getMessage());
        }
    }

    /**
     * Valida si el token es válido para un usuario
     * @param token JWT token
     * @param user Usuario a validar
     * @return true si el token es válido, false en caso contrario
     */
    public boolean isTokenValid(String token, User user) {
        try {
            final String username = extractUsername(token);
            return (username.equals(user.getEmail())) && !isTokenExpired(token);
        } catch (Exception e) {
            return false; // Si hay error, el token no es válido
        }
    }

    /**
     * Verifica si el token ha expirado
     */
    private boolean isTokenExpired(String token) {
        try {
            return parseClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true; // Si hay error al parsear, consideramos expirado
        }
    }

    /**
     * Parsea el token y extrae los claims (datos)
     */
    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token expirado");
        } catch (UnsupportedJwtException e) {
            throw new RuntimeException("Token no soportado");
        } catch (MalformedJwtException e) {
            throw new RuntimeException("Token malformado");
        } catch (SignatureException e) {
            throw new RuntimeException("Firma del token inválida");
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Token vacío");
        }
    }

    /**
     * Obtiene la clave de firma desde el secret configurado
     * Soporta tanto Base64 como texto plano
     */
    private Key getSigningKey() {
        byte[] keyBytes;

        // Detectar si es Base64 válido
        if (isValidBase64(secret)) {
            try {
                keyBytes = Decoders.BASE64.decode(secret);
                System.out.println("✅ Secret decodificado desde Base64");
            } catch (Exception e) {
                // Si falla, usar como texto plano
                keyBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                System.out.println("⚠️ Usando secret como texto plano");
            }
        } else {
            // No es Base64, usar como texto plano directamente
            keyBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            System.out.println("⚠️ Secret en texto plano detectado");
        }

        // Validar longitud mínima para HS256 (256 bits = 32 bytes)
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException(
                    "jwt.secret debe tener al menos 32 caracteres/bytes para HS256. " +
                            "Actual: " + keyBytes.length + " bytes"
            );
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Verifica si un string es Base64 válido
     */
    private boolean isValidBase64(String str) {
        // Base64 solo contiene: A-Z, a-z, 0-9, +, /, =
        return str.matches("^[A-Za-z0-9+/]*={0,2}$");
    }
}
