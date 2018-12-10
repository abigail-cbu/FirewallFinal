package Firewall;

import java.util.Random;

public class Packet {

    private String IPAddress;
    private String Payload;
    private final int GOOD_BOUND = 256;
    private final int BAD_BOUND = 500;

    public String GeneratePacket(Boolean status) {
        return generateRandomIPAddress(status) + generateRandomPacketPayload();
    }

    public String GeneratePacketWithKnownURL(String url) {
        return url + generateRandomPacketPayload();
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
