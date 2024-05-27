package com.example.springsecurityjwt.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CustomUserInfoDto {
    private Long id;

    private String username;

    private String password;

    private String role;
}
