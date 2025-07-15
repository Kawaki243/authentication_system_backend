# Use an official OpenJDK runtime as a parent image
FROM openjdk:17-jdk-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the jar file from your local machine to the container
# Replace 'target/app.jar' with your actual jar file path
COPY target/authenticationSystem.jar app.jar

# Expose the port your app runs on (update if needed)
EXPOSE 8080

# Run the jar file
ENTRYPOINT ["java","-jar","app.jar"]
