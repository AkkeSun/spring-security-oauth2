package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/loginPage")
    public ResponseEntity<?> login(){
        return ResponseEntity.ok("로그인이 필요합니다");
    }
}
