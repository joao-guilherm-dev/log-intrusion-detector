package com.security.logdetector.rules;

import com.security.logdetector.model.AlertEvent;
import com.security.logdetector.model.LogEntry;

import java.util.Optional;

public interface DetectionRule {
    Optional<AlertEvent> process(LogEntry entry);
    String getRuleName();
}
