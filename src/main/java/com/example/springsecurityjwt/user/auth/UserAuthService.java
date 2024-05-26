package com.example.springsecurityjwt.user.auth;

import com.example.springsecurityjwt.user.User;
import com.example.springsecurityjwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserAuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signup(UserAuthDto userAuthDto) {
        if(userRepository.existsByUsername(userAuthDto.getUsername())) {
            throw new IllegalArgumentException("Username is already taken");
        }
        userRepository.existsByUsername(userAuthDto.getUsername());
        User user = User.createUser(userAuthDto);
        user.encodePassword(passwordEncoder);
        userRepository.save(user);
    }
}
