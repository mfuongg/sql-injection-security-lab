package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.AttackPayload;
import com.example.sqlinjectiondemo.repository.AttackPayloadRepository;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;

@Service
public class AttackPayloadService {

    private final AttackPayloadRepository attackPayloadRepository;

    public AttackPayloadService(AttackPayloadRepository attackPayloadRepository) {
        this.attackPayloadRepository = attackPayloadRepository;
    }

    public List<AttackPayload> findAll() {
        return attackPayloadRepository.findAll().stream()
                .sorted(Comparator.comparing(AttackPayload::getId))
                .toList();
    }
}
