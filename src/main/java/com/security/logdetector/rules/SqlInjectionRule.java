package com.security.logdetector.rules;

import com.security.logdetector.model.AlertEvent;
import com.security.logdetector.model.LogEntry;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Pattern;

@Component
public class SqlInjectionRule implements DetectionRule {

    private static final Pattern SQLI_PATTERN = Pattern.compile(
        "(?i)('|"|%27|%22)\\s*(or|and)\\s*\\d=\\d|union\\s+select|select\\s+.*\\s+from|drop\\s+table|exec\\s*\\(",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getRuleName() {
        return "SQL_INJECTION_DETECTION";
    }

    @Override
    public Optional<AlertEvent> process(LogEntry entry) {
        if (SQLI_PATTERN.matcher(entry.rawLine()).find()) {
            return Optional.of(new AlertEvent(
                getRuleName(),
                "CRITICAL",
                "Tentativa de SQL Injection identificada na requisição: " + entry.rawLine(),
                entry.ipAddress(),
                entry.timestamp() != null ? entry.timestamp() : LocalDateTime.now()
            ));
        }
        return Optional.empty();
    }
}
