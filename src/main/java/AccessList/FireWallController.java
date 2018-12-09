package AccessList;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AccessList stores salted urls (code from miniPassword.java from Security book)
 */
public class FireWallController {

    private final int IP_MAX_LENGTH = 16;
    private List<Object> accessList = new ArrayList<Object>(Arrays.asList(
            "128.60.25.3",
            "127.128.32.5",
            "61.110.4.11"
    ));

    /**
     * Checks packet against FireWall
     *
     * @param packet
     * @return
     * @throws Exception
     */
    public Object checkPacket(Object packet) throws Exception {
        String address = addressExtractor(packet);
        if (addUrl(address)) {
            return packet;
        } else {
            Logger log = new Logger();
            log.logReject(packet);
            return address + " attempted to break firewall!!!";
        }
    }

    /**
     * Extracts a packet and parses it to get the Address and Payload.
     * Assumes the packet format is a AccessList Address (16 characters) followed by the Packet Payload (64 characters)
     * example: ip.ljust(16) + ''.join(random.choice(string.ascii_letters) for _ in range(64))
     *
     * @param packet
     */
    public String addressExtractor(Object packet) throws Exception {

        // always get the 1st 16 characters of the packet
        String ipAddress = StringUtils.substring(packet.toString(), 0, IP_MAX_LENGTH);

        // fix url if contains characters at the end
        ipAddress = removeBadCharactersFromIP(ipAddress);

        return ipAddress;
    }

    /**
     * Gets url, encode it and then saves it a list.
     *
     * @param address
     * @return true if url was added to the list
     */
    private boolean addUrl(String address) throws Exception {
        // 1. check if valid url / ip address

        // 2. encrypt url

        // 3. add url to AccessList
        if (accessList.contains(address)) {
            return true;
        } else if (validIP(address)) {
            accessList.add(address);
            return true;
        }

        return false; // url wasn't added because it is invalid or already in the list
    }

    /**
     * Checks if url has access
     *
     * @param address
     * @return true if url is within the access list
     */
    public boolean hasAccess(String address) {
        if (accessList.contains(address)) {
            return true;
        }

        return false;
    }

    /**
     * returns the SHA-256 hash of the provided preimage as a String
     */
    private byte[] encodeUrl(String url) throws Exception {
        MessageDigest md = null;
        md = MessageDigest.getInstance("SHA-256");
        md.update(url.getBytes("UTF-8"));
        byte raw[] = md.digest();
        return Base64.encodeBase64(raw);
    }

    /**
     * Validates urls / ip addresses
     *
     * @param ip
     * @return false if the parameter is empty or not a valid ip
     */
    private boolean validIP(String ip) {
        try {
            if (ip == null || ip.length() == 0) {
                return false;
            }

            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }

            // check for any letters in the ip address
            for (int i = 0; i < 4; i++) {
                if (parts[i].contains("[^\\d.]")) {
                    return false;
                }
            }

            for (String s : parts) {
                int i = Integer.parseInt(s);
                if ((i < 0) || (i > 255)) {
                    return false;
                }
            }
            if (ip.endsWith(".")) {
                return false;
            }

            return true;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }

    /**
     * Removes hanging characters from the 16 character pickup from the packet.
     * Handles any urls within 16 characters.
     * Handles the following types of urls:
     * 1.1.1.1aa
     * 1.1.1.a11
     * 1.1.1.1a1
     *
     * @param ip
     * @return empty string if it is an invalid ip address,
     * for example, if it found a character instead of numbers in the ip address
     */
    private String removeBadCharactersFromIP(String ip) {
        String[] parts = ip.split("\\.");

        for (int i = 0; i < 3; i++) {
            if (parts[i].contains("[^\\d.]")) {
                return "";
            }
        }

        // check if last numbers contain any characters
        if (!parts[3].matches("[0-9]+")) {
            boolean removeCharacters = false;
            int index = 0;

            // check if last parts number is valid
            // this makes sure we don't have letters in ip address (i.e. 1.1.1.1aa or 1.1.1.a11 or 1.1.1.1a1)
            while (index < parts[3].length() && !removeCharacters) {
                char c = parts[3].charAt(index);
                try {
                    Integer.parseInt(String.valueOf(c));
                    index++;
                } catch (NumberFormatException e) {
                    removeCharacters = true;
                }
            }

            // remove characters if necessary from last parts number
            String badCharacters = parts[3].substring(index, parts[3].length());
            parts[3] = parts[3].replaceAll(badCharacters, "");
            if (parts[3].length() == 0) {
                return "";
            }

        }

        // return fixed ip address
        return parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];
    }
}
