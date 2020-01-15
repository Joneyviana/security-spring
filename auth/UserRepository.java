package com.security.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer>
{
    Optional<User> findByEmail(String email);
    Optional<User> findByName(String name);
    
    @Query(value="Select u from User u join fetch u.roles")
    List<User> listar();
}
