FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY . .
# -pl orchestrator -am : construiește orchestrator + dependențele lui (contracts)
RUN mvn -q -pl orchestrator -am -Dmaven.test.skip=true package

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/orchestrator/target/orchestrator-*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]