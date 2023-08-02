package com.security.springsecurity.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

  Optional<User> findByEmail(String email); // kullanıcıyı e posta ile bulmaya çalısıyor cunkü unique

}
