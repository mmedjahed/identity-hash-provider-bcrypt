# bcrypt-hash-generator
This contains the Client for generate BCRYPT Hash and the Salt Value for a given plain text password.

## How to use this Hash Generator

1. Clone this repository.
2. Build this module using `mvn clean install`
3. Then the executable jar will be built inside the target folder.
      - `utility/bcrypt-hash-generator/target/`
4. Execute the jar using command `java -jar <jar_file.jar>`\
      - ex : `java -jar bcrypt-hash-generator-0.1.3-SNAPSHOT.jar`
5. It will prompt you to enter the password. Type the password and press enter.
6. Then the script will output the Hashed Password and the Salt value.
