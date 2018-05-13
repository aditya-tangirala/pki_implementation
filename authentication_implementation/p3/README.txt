PART 3

To run from command prompt: 

Go to the location where the jar files are saved. On 4 different windows, run the following commands:

1. Run the command java -jar Trudy.jar
2. Run the command java -jar KDC.jar
3. Run the command java -jar Bob.jar
4. Run the command java -jar Alice.jar

The communication messages appear on screen. The ECB and CBC outputs for the last 2 messages appear on the screen. The messages are for:
a. Actual communication with Alice - authenticated in ECB and CBC mode.
b. Session 1 with TRudy - authenticated only in ECB and not in CBC (Exception is raised).
c. session 2 with Trudy - never completed, so session ends.

In the window for Bob.jar, an Exception is raised for CBC mode in the 2nd session with Trudy. This is because decryption of N3-1 is not valid when CBC mode is used and the communication ends without Trudy being authenticated. When ECB mode is used however, Trudy gets authenticate with a successful reflection attack.