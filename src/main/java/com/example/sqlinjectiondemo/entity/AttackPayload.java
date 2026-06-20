package com.example.sqlinjectiondemo.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "attack_payloads")
public class AttackPayload {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 120)
    private String name;

    @Column(nullable = false, length = 500)
    private String payload;

    @Column(name = "attack_type", nullable = false, length = 100)
    private String attackType;

    @Column(length = 800)
    private String description;

    @Column(name = "expected_vulnerable", length = 500)
    private String expectedVulnerable;

    @Column(name = "expected_secure", length = 500)
    private String expectedSecure;

    public AttackPayload() {
    }

    public AttackPayload(String name, String payload, String attackType, String description,
                         String expectedVulnerable, String expectedSecure) {
        this.name = name;
        this.payload = payload;
        this.attackType = attackType;
        this.description = description;
        this.expectedVulnerable = expectedVulnerable;
        this.expectedSecure = expectedSecure;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getExpectedVulnerable() {
        return expectedVulnerable;
    }

    public void setExpectedVulnerable(String expectedVulnerable) {
        this.expectedVulnerable = expectedVulnerable;
    }

    public String getExpectedSecure() {
        return expectedSecure;
    }

    public void setExpectedSecure(String expectedSecure) {
        this.expectedSecure = expectedSecure;
    }
}
