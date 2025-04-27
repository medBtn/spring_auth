package com.example.springauth.security.services;

import com.example.springauth.model.User;
import com.example.springauth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
    
    
    // Method to unlock user account
    @Transactional
    public boolean unlockWhenTimeExpired(User user) {
        long lockTimeInMillis = user.getLockTime();
        long currentTimeInMillis = System.currentTimeMillis();
        
        if (lockTimeInMillis + 24 * 60 * 60 * 1000 < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedAttempt(0);
            userRepository.save(user);
            
            return true;
        }
        
        return false;
    }
}