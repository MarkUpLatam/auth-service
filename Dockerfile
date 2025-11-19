# ====== BUILD STAGE ======
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Copiamos pom y descargamos dependencias para cache
COPY pom.xml .
RUN mvn -q -e -B dependency:go-offline

# Copiamos el código fuente
COPY src ./src

# Build del proyecto (sin tests)
RUN mvn clean package -DskipTests

# ====== RUN STAGE ======
FROM eclipse-temurin:17-jre
WORKDIR /app

# Copiamos el JAR generado
COPY --from=build /app/target/*.jar app.jar

# Puerto de spring (Render lo detecta automáticamente)
EXPOSE 8080

# Arrancamos el microservicio
ENTRYPOINT ["java", "-jar", "app.jar"]
