package com.app.demo.repository;

import com.app.demo.model.LoginToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginTokenRepository extends JpaRepository<LoginToken, Long> {
    Optional<LoginToken> findTopByEmailOrderByCreatedAtDesc(String email);

    Optional<LoginToken> findByToken(String token);

    @Modifying
    @Query("UPDATE LoginToken o SET o.used = true WHERE o.email = :email AND o.used = false")
    void expireAllOldToken(@Param("email") String email);
}
