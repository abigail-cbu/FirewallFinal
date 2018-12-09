Description of Final for CSC 513:
This course introduces you to security issues and current security software tools.

For your final exam you’ll look at one specific software tool, a firewall.  Please build your firewall from the following objects:

 1. An Access list to keep URLs - **Found in src/main/java/Firewall/AccessListController.java**
 
        With a method to add a URL
        And a method to find a URL within the access list

 2. A packet - **Found in src/main/java/Firewall/AccessListController.java**
 
        Assume the packet format is a URL Address (16 characters) followed by the Packet Payload (64 characters)
        With a method to extract the URL address.

 3. A Log to keep rejected URL’s. - **Found in Found in src/main/java/Firewall/Logger.java**
 
        With a method that accepts a URL and stores it in a Log entry.
        The Log entry should be 16 characters long.
 

Your firewall program should accept a packet as input, extract it’s URL

Look up the URL in the Access List

    If the Firewall is in the Access List, return the packet
    Otherwise, Report an attempt to penetrate the firewall in the firewall log.

 

To test your program use the following URL’s for the access list:

    128.60.25.3
    127.128.32.5
    61.110.4.11

Then pass it each of these 3 addresses, plus 0.0.0.0 and 128.128.128.128

 

Grading Criteria:

               Max. 50 points for following the structure above.

               Max. 25 points for a correctly working program.

               Max. 25 points for test cases run. 

Test Cases - **Found in src/test/java/MainTest.java**