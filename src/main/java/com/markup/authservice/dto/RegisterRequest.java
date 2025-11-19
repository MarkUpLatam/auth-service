package com.markup.authservice.dto;
import com.markup.authservice.entity.Role;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String identification;
    private String province;
    private String city;
    private String password;
    private String amount;
    private Role role;
    private String requestType;
}
