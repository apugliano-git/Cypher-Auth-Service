FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
# The pinned Wrapper checksum is for ZIP; without unzip it switches to a different archive.
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*
COPY pom.xml mvnw ./
COPY .mvn ./.mvn
COPY src ./src
RUN ./mvnw -B clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
ARG APP_UID=1000
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
RUN apk upgrade --no-cache libpng zlib && addgroup -S -g "$APP_UID" cypher && adduser -S -D -H -u "$APP_UID" -G cypher cypher
USER cypher
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
