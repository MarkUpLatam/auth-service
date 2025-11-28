package com.markup.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class NotificationRequest {
    private String topic;
    private String email;
    private String firstName;
    private String lastName;
    private String password;
}
