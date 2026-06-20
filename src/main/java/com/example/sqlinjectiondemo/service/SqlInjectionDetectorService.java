package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.model.DetectionResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class SqlInjectionDetectorService {

    private static final List<Rule> RULES = List.of(
            new Rule("BOOLEAN BYPASS", Pattern.compile("(?i)'\\s*or\\s*('?[0-9a-z_]+)?\\s*=\\s*('?[0-9a-z_]+)?"), 42),
            new Rule("UNION SELECT", Pattern.compile("(?i)union\\s+select"), 55),
            new Rule("STACKED QUERY", Pattern.compile(";\\s*(drop|alter|update|delete|insert)\\b", Pattern.CASE_INSENSITIVE), 70),
            new Rule("COMMENT OPERATOR", Pattern.compile("--|#|/\\*|\\*/"), 18),
            new Rule("TIME DELAY", Pattern.compile("(?i)(sleep\\s*\\(|benchmark\\s*\\()"), 65),
            new Rule("SCHEMA ENUMERATION", Pattern.compile("(?i)information_schema|sys\\.|mysql\\."), 50),
            new Rule("ORDER PROBE", Pattern.compile("(?i)order\\s+by\\s+\\d+"), 28),
            new Rule("BOOLEAN TRUE", Pattern.compile("(?i)or\\s+1=1|or\\s+'1'='1'"), 35),
            new Rule("UNSAFE QUOTE", Pattern.compile("['\"]"), 10)
    );

    public DetectionResult inspect(String username, String password) {
        String combined = ((username == null ? "" : username) + " " + (password == null ? "" : password))
                .toLowerCase(Locale.ROOT);

        List<String> matches = new ArrayList<>();
        int score = 0;

        for (Rule rule : RULES) {
            if (rule.pattern().matcher(combined).find()) {
                matches.add(rule.name());
                score += rule.weight();
            }
        }

        if (combined.contains("'") && combined.contains("=")) {
            score += 8;
        }
        if (matches.size() >= 2) {
            score += 12;
        }
        if (combined.length() > 40) {
            score += 5;
        }

        score = Math.min(score, 100);
        String level = score >= 85 ? "CRITICAL"
                : score >= 60 ? "HIGH"
                : score >= 30 ? "MEDIUM"
                : "LOW";
        boolean suspicious = score >= 30 || !matches.isEmpty();
        String summary = suspicious
                ? "Rủi ro " + level + " · Quy tắc khớp: " + String.join(", ", matches)
                : "Không phát hiện chỉ báo SQL injection rõ ràng";

        return new DetectionResult(suspicious, matches, score, level, summary);
    }

    private record Rule(String name, Pattern pattern, int weight) {
    }
}
