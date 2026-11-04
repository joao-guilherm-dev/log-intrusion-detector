package com.security.logdetector.model;

import java.time.LocalDateTime;

public record LogEntry(
    LocalDateTime timestamp,
    String ipAddress,
    String username,
    String action,
    String rawLine
) {}
