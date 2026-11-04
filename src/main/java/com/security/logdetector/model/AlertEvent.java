package com.security.logdetector.model;

import java.time.LocalDateTime;

public record AlertEvent(
    String ruleName,
    String severity,
    String description,
    String targetIp,
    LocalDateTime timestamp
) {}
