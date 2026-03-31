package com.app.demo.repository;

import com.app.demo.enums.AuthProvider;
import com.app.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByEmail(String email);
    boolean existsByEmailAndIdNot(String email, Long id);
    Optional<User> findByEmail(String email);
    User findByProviderAndProviderId(AuthProvider provider, String providerId);
}
