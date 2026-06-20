package com.example.sqlinjectiondemo.repository;

import com.example.sqlinjectiondemo.entity.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {
}
