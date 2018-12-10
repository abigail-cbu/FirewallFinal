import Firewall.AccessListController;
import Firewall.Logger;
import Firewall.Packet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Random;

/**
 * Description: MainTest contains JUnits tests that will test the
 * Firewall package
 * and make sure that the project fulfills the requirements stated in the README.md file
 * <p>
 * Output:
 * Testing known URLS:
 * encrypted string check: HiTpyY6MQaymlIYTjG/MeA== <-- during addUrl()
 * encrypted string check: 5arPYTYbi7wmmZKzYcxR8w==
 * encrypted string check: yaYLSnwqqDjOssHUw9VGPg==
 * encrypted string check: HiTpyY6MQaymlIYTjG/MeA==
 * encrypted string check: 5arPYTYbi7wmmZKzYcxR8w==
 * encrypted string check: yaYLSnwqqDjOssHUw9VGPg==
 * encrypted string check: xVSJyEG49nLwTbVXTMLFZQ==
 * encrypted string check: Y3AcuvgaajD1sacWele5ug==
 * The following are packages that have been rejected:
 * 300.300.300.300
 * * testUrls() Passed **
 * Testing unknown packets:
 * encrypted string check: HiTpyY6MQaymlIYTjG/MeA==
 * encrypted string check: 5arPYTYbi7wmmZKzYcxR8w==
 * encrypted string check: yaYLSnwqqDjOssHUw9VGPg==
 * url1: 136.206.138.185 <-- randomly generated url
 * url3: 342.28.423.25 <-- randomly generated url
 * The following are packages that have been rejected:
 * 300.300.300.300
 * 342.28.423.25iMV <-- randomly generated url
 * url2: 1.1.1.1
 * encrypted string check: 7FemYmB9GDIQq+oHq7tqPg==
 * * testPacketInputs() Passed **
 */
public class MainTest {

    private final int GOOD_BOUND = 256;
    private final int BAD_BOUND = 500;

    @Test
    public void testAllTests() {
        testUrls();
        testPacketInputs();
    }

    @Test
    public void testUrls() {
        System.out.println("Testing known URLS:");
        try {
            AccessListController ac = new AccessListController();
            Logger log = new Logger();

            // testing valid urls that already are in the Firewall
            String url1 = "128.60.25.3";
            Assertions.assertEquals(url1, ac.checkPacket(url1));
            Assertions.assertTrue(ac.hasAccess(url1));

            String url2 = "127.128.32.5";
            Assertions.assertEquals(url2, ac.checkPacket(url2));
            Assertions.assertTrue(ac.hasAccess(url2));

            String url3 = "61.110.4.11";
            Assertions.assertEquals(url3, ac.checkPacket(url3));
            Assertions.assertTrue(ac.hasAccess(url3));

            // testing invalid urls that are not in the Firewall
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
            AccessListController ac = new AccessListController();
            Logger log = new Logger();
            Packet packetCreation = new Packet();

            // testing random packets generator
            String url1 = packetCreation.generateRandomIPAddress(true);
            System.out.println("url1: " + url1);
            String packet1 = packetCreation.GeneratePacketWithKnownURL(url1);
            Assertions.assertEquals(url1, ac.addressExtractor(packet1));
            Assertions.assertFalse(ac.hasAccess(ac.addressExtractor(packet1)));

            String url3 = packetCreation.generateRandomIPAddress(false);
            System.out.println("url3: " + url3);
            String packet3 = packetCreation.GeneratePacketWithKnownURL(url3);
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
            String packet2 = packetCreation.GeneratePacketWithKnownURL(url2);
            Assertions.assertEquals(url2, ac.addressExtractor(packet2));
            Assertions.assertEquals(packet2, ac.checkPacket(packet2));

            System.out.println("** testPacketInputs() Passed **");

        } catch (Exception ex) {
            System.out.println("** testPacketInputs() Failed **");
        }
    }
}
