package com.github.marceloasfilho.springsecurityjwt.service;

import com.github.marceloasfilho.springsecurityjwt.dto.AuthenticationRequestDTO;
import com.github.marceloasfilho.springsecurityjwt.dto.AuthenticationResponseDTO;
import com.github.marceloasfilho.springsecurityjwt.dto.RegisterRequestDTO;
import com.github.marceloasfilho.springsecurityjwt.entity.Role;
import com.github.marceloasfilho.springsecurityjwt.entity.User;
import com.github.marceloasfilho.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponseDTO register(RegisterRequestDTO register) {
        var user = User.builder()
                .firstname(register.firstname())
                .lastname(register.lastname())
                .email(register.email())
                .password(this.passwordEncoder.encode(register.password()))
                .role(Role.USER)
                .build();
        User save = this.userRepository.save(user);
        var token = this.jwtService.generateToken(save);
        return AuthenticationResponseDTO.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponseDTO authenticate(AuthenticationRequestDTO authentication) {
        this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authentication.email(), authentication.password()));
        var user = this.userRepository.findByEmail(authentication.email()).orElseThrow();
        var token = this.jwtService.generateToken(user);
        return AuthenticationResponseDTO.builder()
                .token(token)
                .build();
    }
}
