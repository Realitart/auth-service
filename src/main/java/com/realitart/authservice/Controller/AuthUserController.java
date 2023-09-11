package com.realitart.authservice.Controller;

import com.realitart.authservice.Dtos.AuthUserDto;
import com.realitart.authservice.Dtos.tokenDto;
import com.realitart.authservice.Entity.AuthUser;
import com.realitart.authservice.Service.AuthUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthUserController {
    @Autowired
    private AuthUserService authUserService;

    @PostMapping("/login")
    public ResponseEntity<tokenDto> login(@RequestBody AuthUserDto dto){
        tokenDto token = authUserService.login(dto);
        if(token == null){
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(token);
    }

    @PostMapping("/validate")
    public ResponseEntity<tokenDto> validate(@RequestParam String token){
        tokenDto tokenDto = authUserService.validate(token);
        if(tokenDto == null)
            return ResponseEntity.badRequest().build();
        return ResponseEntity.ok(tokenDto);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthUser> register(@RequestBody AuthUserDto dto){
        AuthUser user = authUserService.save(dto);
        if(user == null){
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(user);
    }
}
