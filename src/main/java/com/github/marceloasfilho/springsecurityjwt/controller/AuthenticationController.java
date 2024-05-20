package com.github.marceloasfilho.springsecurityjwt.controller;

import com.github.marceloasfilho.springsecurityjwt.dto.AuthenticationRequestDTO;
import com.github.marceloasfilho.springsecurityjwt.dto.AuthenticationResponseDTO;
import com.github.marceloasfilho.springsecurityjwt.dto.RegisterRequestDTO;
import com.github.marceloasfilho.springsecurityjwt.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDTO> register(@RequestBody RegisterRequestDTO register) {
        return new ResponseEntity<>(this.authenticationService.register(register), HttpStatus.OK);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@RequestBody AuthenticationRequestDTO authentication) {
        return new ResponseEntity<>(this.authenticationService.authenticate(authentication), HttpStatus.OK);
    }
}
