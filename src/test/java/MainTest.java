import AccessList.FireWallController;
import AccessList.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Random;

/**
 * Description: MainTest contains JUnits tests that will test the
 * AccessList package
 * and make sure that the project fulfills the requirements stated in the README.md file
 *
 * Output:
 Testing known URLS:
 The following are packages that have been rejected:
 300.300.300.300
 ** testUrls() Passed **
 Testing unknown packets:
 url1: 255.118.165.246 <-- randomly generated
 url3: 143.131.450.486 <-- randomly generated
 The following are packages that have been rejected:
 300.300.300.300
 143.131.450.486J <-- randomly generated
 url2: 1.1.1.1
 ** testPacketInputs() Passed **
 */
public class MainTest {

    private final int GOOD_BOUND = 256;
    private final int BAD_BOUND = 500;

    @Test
    public void testAllTests(){
        testUrls();
        testPacketInputs();
    }

    @Test
    public void testUrls() {
        System.out.println("Testing known URLS:");
        try {
            FireWallController ac = new FireWallController();
            Logger log = new Logger();

            // testing valid urls that already are in the AccessList
            String url1 = "128.60.25.3";
            Assertions.assertEquals(url1, ac.checkPacket(url1));
            Assertions.assertTrue(ac.hasAccess(url1));

            String url2 = "127.128.32.5";
            Assertions.assertEquals(url2, ac.checkPacket(url2));
            Assertions.assertTrue(ac.hasAccess(url2));

            String url3 = "61.110.4.11";
            Assertions.assertEquals(url3, ac.checkPacket(url3));
            Assertions.assertTrue(ac.hasAccess(url3));

            // testing invalid urls that are not in the AccessList
            String url4 = "0.0.0.0";
            Assertions.assertFalse(ac.hasAccess(url4));
            Assertions.assertEquals(url4, ac.checkPacket(url4));
            Assertions.assertTrue(ac.hasAccess(url4));

            String url5 = "128.128.128.128";
            Assertions.assertFalse(ac.hasAccess(url5));
            Assertions.assertEquals(url5, ac.checkPacket(url5));
            Assertions.assertTrue(ac.hasAccess(url5));

            String url6 = "300.300.300.300"; // testing invalid ip
            Assertions.assertFalse(ac.hasAccess(url6));
            Assertions.assertEquals("300.300.300.300 attempted to break firewall!!!", ac.checkPacket(url6));
            Assertions.assertTrue(log.displayRejects().contains(url6));

            System.out.println("** testUrls() Passed **");

        } catch (Exception ex) {
            System.out.println("** testUrls() Failed **");
        }
    }

    @Test
    public void testPacketInputs() {
        System.out.println("Testing unknown packets:");
        try {
            FireWallController ac = new FireWallController();
            Logger log = new Logger();

            // testing random packets generator
            String url1 = generateRandomIPAddress(true);
            System.out.println("url1: " + url1);
            String packet1 = url1 + generateRandomPacketPayload();
            Assertions.assertEquals(url1, ac.addressExtractor(packet1));
            Assertions.assertFalse(ac.hasAccess(ac.addressExtractor(packet1)));

            String url3 = generateRandomIPAddress(false);
            System.out.println("url3: " + url3);
            String packet3 = url3 + generateRandomPacketPayload();
            Assertions.assertEquals(url3, ac.addressExtractor(packet3));
            Assertions.assertFalse(ac.hasAccess(ac.addressExtractor(packet3)));

            boolean success = ac.checkPacket(packet3).equals(packet3);
            if (success) {
                Assertions.assertFalse(log.displayRejects().contains(url3));
            } else {
                Assertions.assertTrue(log.displayRejects().contains(url3));
            }

            // testing known ips in packets
            String url2 = "1.1.1.1";
            System.out.println("url2: " + url2);
            String packet2 = url2 + generateRandomPacketPayload();
            Assertions.assertEquals(url2, ac.addressExtractor(packet2));
            Assertions.assertEquals(packet2, ac.checkPacket(packet2));

            System.out.println("** testPacketInputs() Passed **");

        } catch (Exception ex) {
            System.out.println("** testPacketInputs() Failed **");
        }
    }

    public String generateRandomIPAddress(boolean getGoodIPAddress) {
        Random r = new Random();
        if (getGoodIPAddress) {
            return r.nextInt(GOOD_BOUND) + "." + r.nextInt(GOOD_BOUND) + "." + r.nextInt(GOOD_BOUND) + "." + r.nextInt(GOOD_BOUND);
        } else {
            return r.nextInt(BAD_BOUND) + "." + r.nextInt(BAD_BOUND) + "." + r.nextInt(BAD_BOUND) + "." + r.nextInt(BAD_BOUND);
        }
    }

    public String generateRandomPacketPayload() {
        String AB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        Random rnd = new Random();
        int maxLength = 64;
        StringBuilder sb = new StringBuilder(maxLength);

        for (int i = 0; i < maxLength; i++) {
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        }

        return sb.toString();
    }
}
