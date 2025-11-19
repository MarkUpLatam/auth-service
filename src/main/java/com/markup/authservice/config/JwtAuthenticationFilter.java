package com.markup.authservice.config;

import com.markup.authservice.entity.User;
import com.markup.authservice.repository.UserRepository;
import com.markup.authservice.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepository;

    /**
     * Rutas públicas que NO requieren JWT
     * IMPORTANTE: Deben terminar en / para que startsWith() funcione
     */
    private static final String[] PUBLIC_PATHS = {
            "/api/auth/",           // ✅ Captura /api/auth/register, /api/auth/login
            "/swagger-ui",          // ✅ Captura /swagger-ui/index.html, etc.
            "/v3/api-docs",         // ✅ Captura /v3/api-docs/swagger-config
            "/api-docs/",
            "/swagger-resources/",
            "/webjars/",
            "/actuator/",
            "/favicon.ico",
            "/error"
    };

    /**
     * Verifica si la ruta es pública comparando con los prefijos
     */
    private boolean isPublicPath(String path) {
        for (String publicPath : PUBLIC_PATHS) {
            if (path.startsWith(publicPath)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String requestPath = request.getRequestURI();

        // ===== PASO 1: Verificar si es ruta pública =====
        if (isPublicPath(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        // ===== PASO 2: Extraer header Authorization =====
        String authHeader = request.getHeader("Authorization");

        // Si no hay header o no empieza con "Bearer ", continuar sin autenticar
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // ===== PASO 3: Extraer JWT (quitar "Bearer ") =====
            String jwt = authHeader.substring(7);

            // ===== PASO 4: Extraer email del token =====
            String userEmail = jwtService.extractUsername(jwt);

            // ===== PASO 5: Autenticar si no hay autenticación previa =====
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Buscar usuario en BD
                User user = userRepository.findByEmail(userEmail).orElse(null);

                // Validar token y crear autenticación
                if (user != null && jwtService.isTokenValid(jwt, user)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    user,
                                    null,
                                    user.getAuthorities()  // IMPORTANTE: Incluir roles/authorities
                            );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // Establecer autenticación en el contexto de Spring Security
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

        } catch (Exception e) {
            // Si hay error al procesar JWT, solo loguearlo y continuar
            // Spring Security se encargará de bloquear si es necesario
            logger.error("Error procesando JWT: " + e.getMessage());
        }

        // ===== PASO 6: Continuar con la cadena de filtros =====
        filterChain.doFilter(request, response);
    }


}
