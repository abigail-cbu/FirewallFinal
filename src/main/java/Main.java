import AccessList.AccessController;
import AccessList.Logger;

/**
 * Abigail Lu
 * CSC 513 - Final
 * Updated: 12/8/2018
 * Description: The goals for this project can be found in the README.md file.
 * Test cases are found in MainTest.java.
 * AccessList is a package that contains AccessController and Logger
 */
public class Main {

    public static void main(String[] args) throws Exception {
        String url = "";
        testUrls(url);
    }

    public static void testUrls(String url) throws Exception {
        AccessController ac = new AccessController();

        if (ac.hasAccess(url)) {
            ac.addUrl(url);
        } else {
            Logger log = new Logger();
            log.logReject(url);
        }
    }
}
