FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY . .
RUN mvn -q -pl ingestion -am -Dmaven.test.skip=true package

FROM maven:3.9-eclipse-temurin-21
WORKDIR /app
COPY --from=build /src/ingestion/target/ingestion-*.jar app.jar
# Workspace-ul partajat (clonele proiectelor) e montat aici de compose.
VOLUME ["/workspace"]
ENTRYPOINT ["java", "-jar", "app.jar"]