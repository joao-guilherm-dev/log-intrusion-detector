FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
COPY . .
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/log-intrusion-detector-1.0.0.jar app.jar

RUN mkdir -p /var/log && touch /var/log/app-auth.log

ENTRYPOINT ["java", "-jar", "app.jar"]
