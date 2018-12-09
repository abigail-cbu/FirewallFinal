import AccessList.AccessController;
import AccessList.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Description: MainTest contains JUnits tests that will test the
 * AccessList package
 * and make sure that the project fulfills the requirements stated in the README.md file
 */
public class MainTest {

    @Test
    public void testUrls() {

        try {
            AccessController ac = new AccessController();

            String url1 = "128.60.25.3";
            Assertions.assertFalse(ac.addUrl(url1)); // false because url is already in the AccessList
            Assertions.assertTrue(ac.hasAccess(url1));

            String url2 = "127.128.32.5";
            Assertions.assertFalse(ac.addUrl(url2)); // false because url is already in the AccessList
            Assertions.assertTrue(ac.hasAccess(url2));

            String url3 = "61.110.4.11";
            Assertions.assertFalse(ac.addUrl(url3)); // false because url is already in the AccessList
            Assertions.assertTrue(ac.hasAccess(url3));

            String url4 = "0.0.0.0";
            Assertions.assertFalse(ac.hasAccess(url4));
            Assertions.assertTrue(ac.addUrl(url4));
            Assertions.assertTrue(ac.hasAccess(url4));

            String url5 = "128.128.128.128";
            Assertions.assertFalse(ac.hasAccess(url5));
            Assertions.assertTrue(ac.addUrl(url5));
            Assertions.assertTrue(ac.hasAccess(url5));

        } catch (Exception ex) {

        }
    }

    @Test
    public void testPacketInputs() {

    }
}
