package com.security.logdetector.rules;

import com.security.logdetector.model.AlertEvent;
import com.security.logdetector.model.LogEntry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class BruteForceRule implements DetectionRule {

    @Value("${detector.thresholds.brute-force-max-attempts}")
    private int maxAttempts;

    @Value("${detector.thresholds.brute-force-window-seconds}")
    private int windowSeconds;

    private final Map<String, List<LocalDateTime>> failedAttempts = new ConcurrentHashMap<>();

    @Override
    public String getRuleName() {
        return "BRUTE_FORCE_DETECTION";
    }

    @Override
    public Optional<AlertEvent> process(LogEntry entry) {
        if (!isFailedLogin(entry)) {
            return Optional.empty();
        }

        String ip = entry.ipAddress();
        LocalDateTime now = entry.timestamp() != null ? entry.timestamp() : LocalDateTime.now();

        failedAttempts.putIfAbsent(ip, new ArrayList<>());
        List<LocalDateTime> timestamps = failedAttempts.get(ip);

        synchronized (timestamps) {
            timestamps.add(now);
            timestamps.removeIf(time -> time.isBefore(now.minusSeconds(windowSeconds)));

            if (timestamps.size() >= maxAttempts) {
                timestamps.clear();
                return Optional.of(new AlertEvent(
                    getRuleName(),
                    "HIGH",
                    String.format("Possível ataque de Brute Force detectado a partir do IP %s (%d falhas em %ds)", ip, maxAttempts, windowSeconds),
                    ip,
                    now
                ));
            }
        }
        return Optional.empty();
    }

    private boolean isFailedLogin(LogEntry entry) {
        String raw = entry.rawLine().toLowerCase();
        return raw.contains("failed password") || raw.contains("login_failure") || raw.contains("401");
    }
}
