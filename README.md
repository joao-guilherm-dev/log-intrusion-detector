# 🛡️ Real-Time Log Intrusion Detection System (IDS Engine)

Um motor leve de análise de logs e detecção de intrusões em tempo real desenvolvido em **Java 21** e **Spring Boot**.

## 🚀 Funcionalidades

- 🔍 **Tail em Tempo Real**: Leitura assíncrona de logs via Apache Commons IO.
- ⚡ **Detecção Rule-Based**:
  - **Brute Force Detection**: Janela deslizante de tentativa de login por IP.
  - **SQL Injection Detection**: Regex em payloads e requisições HTTP.
- 🔔 **Alertas em Webhook**: Notificações via Discord / Slack.
- 🐳 **Docker-Ready**: Pronto para implantação via Docker Compose.

## 🛠️ Como Executar

```bash
git clone https://github.com/SEU_USUARIO/log-intrusion-detector.git
cd log-intrusion-detector
docker-compose up --build
```
