package com.security.logdetector.service;

import com.security.logdetector.engine.LogParserEngine;
import com.security.logdetector.model.LogEntry;
import com.security.logdetector.rules.DetectionRule;
import org.apache.commons.io.input.Tailer;
import org.apache.commons.io.input.TailerListenerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.Duration;
import java.util.List;

@Service
public class LogWatcherService {

    private static final Logger log = LoggerFactory.getLogger(LogWatcherService.class);

    @Value("${detector.log-file-path}")
    private String logFilePath;

    private final LogParserEngine parserEngine;
    private final List<DetectionRule> rules;
    private final AlertService alertService;

    public LogWatcherService(LogParserEngine parserEngine, List<DetectionRule> rules, AlertService alertService) {
        this.parserEngine = parserEngine;
        this.rules = rules;
        this.alertService = alertService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void startMonitoring() {
        File file = new File(logFilePath);
        log.info("Iniciando monitoramento de intrusão no arquivo: {}", file.getAbsolutePath());

        TailerListenerAdapter listener = new TailerListenerAdapter() {
            @Override
            public void handle(String line) {
                if (line != null && !line.isBlank()) {
                    processLine(line);
                }
            }
        };

        Tailer tailer = Tailer.builder()
                .setFile(file)
                .setTailerListener(listener)
                .setDelayDuration(Duration.ofMillis(1000))
                .setTailFromEnd(true)
                .get();

        Thread thread = new Thread(tailer);
        thread.setDaemon(true);
        thread.start();
    }

    private void processLine(String line) {
        LogEntry entry = parserEngine.parse(line);
        for (DetectionRule rule : rules) {
            rule.process(entry).ifPresent(alertService::dispatchAlert);
        }
    }
}
