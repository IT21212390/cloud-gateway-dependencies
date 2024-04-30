FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
ARG JAR_FILE
COPY ${JAR_FILE} clould-gatway.jar
ENTRYPOINT ["java","-jar","/clould-gatway.jar"]
