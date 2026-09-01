FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
ARG APP_UID=1000
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
RUN addgroup -S -g "$APP_UID" cypher && adduser -S -D -H -u "$APP_UID" -G cypher cypher
USER cypher
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
