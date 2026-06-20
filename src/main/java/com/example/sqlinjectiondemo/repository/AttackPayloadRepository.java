package com.example.sqlinjectiondemo.repository;

import com.example.sqlinjectiondemo.entity.AttackPayload;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AttackPayloadRepository extends JpaRepository<AttackPayload, Long> {
    Optional<AttackPayload> findByName(String name);
}
