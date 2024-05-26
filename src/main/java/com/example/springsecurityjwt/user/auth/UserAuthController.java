package com.example.springsecurityjwt.user.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserAuthController {

    private final UserAuthService userAuthService;

    @PostMapping("/signup")
    public String signup(UserAuthDto userAuthDto) {
        userAuthService.signup(userAuthDto);
        return "OK";
    }
}
