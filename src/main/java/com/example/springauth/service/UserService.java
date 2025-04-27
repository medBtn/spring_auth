package com.example.springauth.service;

import com.example.springauth.model.User;
import com.example.springauth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService {

    @Value("${account.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${account.lock-time-duration:900000}")
    private long lockTimeDuration; // 15 minutes in milliseconds by default

    @Autowired
    private UserRepository userRepository;

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Transactional
    public void increaseFailedAttempts(User user) {
        int newFailedAttempts = user.getFailedAttempt() + 1;
        userRepository.findById(user.getId()).ifPresent(u -> {
            u.setFailedAttempt(newFailedAttempts);
            userRepository.save(u);
        });
    }

    @Transactional
    public void resetFailedAttempts(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setFailedAttempt(0);
            userRepository.save(user);
        });
    }

    @Transactional
    public void lockUser(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(System.currentTimeMillis());
        userRepository.save(user);
    }

    @Transactional
    public boolean unlockWhenTimeExpired(User user) {
        long lockTimeInMillis = user.getLockTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + lockTimeDuration < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedAttempt(0);
            userRepository.save(user);
            return true;
        }
        return false;
    }

    public boolean shouldLockAccount(User user) {
        return user.getFailedAttempt() >= maxFailedAttempts;
    }
}