package com.markup.authservice.dto;
import lombok.Data;

@Data
public class LoginResponse {
    private String token;
    private UserData user;

    @Data
    public static class UserData {
        private Long id;
        private String email;
        private String name;
        private String role;
    }
}
