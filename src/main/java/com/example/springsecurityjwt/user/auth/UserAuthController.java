package com.example.springsecurityjwt.user.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserAuthController {

    private final UserAuthService userAuthService;

    @PostMapping("/join")
    public String signup(@RequestBody UserAuthDto userAuthDto) {
        userAuthService.join(userAuthDto);
        return "OK";
    }
}
