package com.security.logdetector.service;

import com.security.logdetector.model.AlertEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${detector.alerts.webhook-url}")
    private String webhookUrl;

    public void dispatchAlert(AlertEvent alert) {
        log.warn("🚨 [INTRUSION ALERT] [{}] Severity: {} | IP: {} | Details: {}",
                alert.ruleName(), alert.severity(), alert.targetIp(), alert.description());

        if (webhookUrl != null && !webhookUrl.contains("dummy-endpoint")) {
            try {
                Map<String, String> payload = Map.of(
                    "content", String.format("🚨 **ALERTA DE SEGURANÇA: %s**\n- **Severidade:** %s\n- **IP Origem:** %s\n- **Descrição:** %s",
                        alert.ruleName(), alert.severity(), alert.targetIp(), alert.description())
                );
                restTemplate.postForEntity(webhookUrl, payload, String.class);
            } catch (Exception e) {
                log.error("Falha ao enviar webhook de alerta: {}", e.getMessage());
            }
        }
    }
}
