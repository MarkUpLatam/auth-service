package com.markup.authservice.client;

import com.markup.authservice.dto.NotificationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor
public class NotificationClient {

    private static final Logger log = LoggerFactory.getLogger(NotificationClient.class);

    private final RestTemplate restTemplate;

    @Value("${notification.service.url}")
    private String notificationUrl;

    public void sendNotification(NotificationRequest request) {
        String url = notificationUrl + "/welcome";

        log.info("URL del servicio de notificaciones: {}", url);
        log.info("Request: email={}, firstName={}, lastName={}", request.getEmail(), request.getFirstName(), request.getLastName());

        try {
            restTemplate.postForEntity(url, request, Void.class);
            log.info("Respuesta recibida del notification-service");
        } catch (Exception e) {
            log.error("Error al llamar al notification-service: {}", e.getMessage());
            throw e;
        }
    }
}

