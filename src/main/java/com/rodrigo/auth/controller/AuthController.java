package com.rodrigo.auth.controller;

import com.rodrigo.auth.dto.LoginDTO;
import com.rodrigo.auth.dto.TokenDTO;
import com.rodrigo.auth.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final TokenService tokenService;

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> autenticar(@RequestBody @Valid LoginDTO dto) {
        UsernamePasswordAuthenticationToken dadosLogin = dto.converter();
        try {
            Authentication authentication = authManager.authenticate(dadosLogin);
            String token = tokenService.gerarToken(authentication);
            return ResponseEntity.ok(new TokenDTO(token, "Bearer"));
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/validarToken")
    public boolean validarToken(@RequestParam("token") String token) {
        try {
            String hash =token.substring(7, token.length());
            return tokenService.isTokenValido(hash);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

}