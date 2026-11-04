package com.security.logdetector.engine;

import com.security.logdetector.model.LogEntry;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class LogParserEngine {

    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    public LogEntry parse(String rawLine) {
        Matcher matcher = IP_PATTERN.matcher(rawLine);
        String ip = matcher.find() ? matcher.group() : "UNKNOWN_IP";

        return new LogEntry(
            LocalDateTime.now(),
            ip,
            "system",
            "LOG_EVENT",
            rawLine
        );
    }
}
