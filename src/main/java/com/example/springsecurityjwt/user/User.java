package com.example.springsecurityjwt.user;

import com.example.springsecurityjwt.user.auth.UserAuthDto;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    private String role;

    public static User createUser(UserAuthDto userAuthDto) {
        User user = new User();
        user.username = userAuthDto.getUsername();
        user.password = userAuthDto.getPassword();
        user.role = "ROLE_USER";
        return user;
    }

    public void encodePassword(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }

    public static User createTempUser(String username, String password, String role) {
        User user = new User();
        user.username = username;
        user.password = password;
        user.role = role;
        return user;
    }
}
