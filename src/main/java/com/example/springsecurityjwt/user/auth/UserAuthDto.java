package com.example.springsecurityjwt.user.auth;

import lombok.Data;

@Data
public class UserAuthDto {
    private String username;
    private String password;
}
