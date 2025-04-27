package com.example.springauth.security;

import com.example.springauth.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private UserService userService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        String username = request.getParameter("username");

        userService.findByUsername(username).ifPresent(user -> {
            // Check if account is locked
            if (!user.isAccountNonLocked()) {
                // Check if lock time has expired
                if (userService.unlockWhenTimeExpired(user)) {
                    new LockedException("Your account has been unlocked. Please try to login again.");
                } else {
                    new LockedException("Your account is locked. Please contact administrator.");
                }
            } else {
                // Account is not locked, increase failed attempts
                userService.increaseFailedAttempts(user);

                // Check if account should be locked
                if (userService.shouldLockAccount(user)) {
                    userService.lockUser(user);
                    throw new LockedException(
                            "Your account has been locked due to 5 failed attempts. It will be unlocked after 15 minutes.");
                }
            }
        });

        super.onAuthenticationFailure(request, response, exception);
    }
}