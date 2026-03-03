# stage 1: build the jar
# uses the full jdk since we need maven to compile
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /build

# copy both projects - build-helper plugin needs java-dpi/src to compile
COPY java-dpi/ java-dpi/
COPY dpi-spring-server/pom.xml dpi-spring-server/pom.xml
COPY dpi-spring-server/src/   dpi-spring-server/src/

# install maven and build, skip tests to keep it fast
RUN apk add --no-cache maven && \
    cd dpi-spring-server && \
    mvn clean package -DskipTests --no-transfer-progress

# stage 2: tiny runtime image
# only the jre, no compile tools → much smaller image
FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="DPI Project"
LABEL description="Deep Packet Inspection Spring Boot AI Server"

# dont run as root
RUN addgroup -S dpi && adduser -S dpi -G dpi
USER dpi

WORKDIR /app

COPY --from=builder /build/dpi-spring-server/target/dpi-spring-server-1.0.0.jar app.jar

EXPOSE 8080

# use 75% of available ram, g1gc is good for latency-sensitive stuff
ENTRYPOINT ["java", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+UseG1GC", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "/app/app.jar"]
