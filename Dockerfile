FROM eclipse-temurin:17-jre
ARG JAR_FILE=build/libs/*.jar

RUN mkdir /logs

COPY ${JAR_FILE} app.jar

RUN chmod 777 /logs

ENTRYPOINT ["java", "-Duser.timezone=Asia/Seoul", "-jar", "app.jar", "--spring.profiles.active=prod"]

VOLUME ["/logs"]
