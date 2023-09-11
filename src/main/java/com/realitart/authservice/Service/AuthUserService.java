package com.realitart.authservice.Service;

import com.realitart.authservice.Configuration.Jwt.JwtProvider;
import com.realitart.authservice.Dtos.AuthUserDto;
import com.realitart.authservice.Dtos.tokenDto;
import com.realitart.authservice.Entity.AuthUser;
import com.realitart.authservice.Repository.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthUserService {
    @Autowired
    AuthRepository authRepository;

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JwtProvider jwtTokenProvider;

    public AuthUser save(AuthUserDto request) {
        Optional<AuthUser> user = authRepository.findByUserName(request.getUsername());
        if (user.isPresent())
            return null;
        String password = passwordEncoder.encode(request.getPassword());
        AuthUser authUser = AuthUser.builder()
                .userName(request.getUsername())
                .password(password)
                .build();
        return authRepository.save(authUser);
    }

    public tokenDto login(AuthUserDto request) {
        Optional<AuthUser> user = authRepository.findByUserName(request.getUsername());
        if (user.isEmpty())
            return null;
        if (passwordEncoder.matches(request.getPassword(), user.get().getPassword())){
            String token = jwtTokenProvider.createToken(user.get());
            return new tokenDto(token);
        }
        return null;
    }

    public tokenDto validate(String token) {
        if (!jwtTokenProvider.validate(token))
            return null;
        String userName = jwtTokenProvider.getUserNameFromToken(token);
        if(authRepository.findByUserName(userName).isEmpty())
            return null;
        return new tokenDto(token);
    }
}
