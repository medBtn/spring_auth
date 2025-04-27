package com.example.springauth.controllers;


import com.example.springauth.model.User;
import com.example.springauth.payload.request.LoginRequest;
import com.example.springauth.payload.request.SignupRequest;
import com.example.springauth.payload.response.JwtResponse;
import com.example.springauth.payload.response.MessageResponse;
import com.example.springauth.repository.UserRepository;
import com.example.springauth.security.jwt.JwtUtils;
import com.example.springauth.security.services.UserDetailsImpl;
import com.example.springauth.security.services.UserDetailsServiceImpl;
import com.example.springauth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    // RoleRepository no longer needed with direct enum roles

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;
    
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    
    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(authentication);
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        // Reset failed attempts on successful login
        userService.resetFailedAttempts(userDetails.getUsername());
        
        return ResponseEntity.ok(new JwtResponse(jwt,
                refreshToken,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail()
               ));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        // No roles to set as they have been removed from the User entity
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@RequestBody String refreshToken) {
        if (jwtUtils.validateJwtToken(refreshToken)) {
            String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
            
            // Create authentication object and set it in the security context
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            String newToken = jwtUtils.generateTokenFromUsername(username, 86400000); // 24 hours
            
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(new JwtResponse(newToken,
                    refreshToken,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail()
                    ));
        }
        
        return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid refresh token!"));
    }
}