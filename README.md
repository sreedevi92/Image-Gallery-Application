# Importing into Eclipse
Eclipse is a very popular Java IDE.  Download and install Eclipse from the
following URL -

https://eclipse.org/

The Eclipse project files are contained in the repository and can be imported
into Eclipse.  Follow t
hese instructions on how to import a project -

http://help.eclipse.org/kepler/index.jsp?topic=%2Forg.eclipse.platform.doc.user%2Ftasks%2Ftasks-importproject.htm


# Java Development Kit (JDK) 8
The application's code uses some features found in JDK 8. Download the JDK

http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html

# Building
The project uses Gradle as the build tool.  You can read more about Gradle here -

https://gradle.org/

The project provides a Gradle wrapper (gradlew).  The Gradle wrapper will download and install the appropriate Gradle version when a command is first executed.

To build the application, run the following Gradle command -

    gradlew build

The build command will create an executable JAR file that will be found in "application/build/libs".

# Running the Application Locally
You can execute the JAR file using the following command

    java -jar ./build/libs/image-gallery-0.1.0.jar

The application should be running at http://localhost:8080/

There are some images in the "application/test-images" folder that you can use to verify your setup.
