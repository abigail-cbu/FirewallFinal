package AccessList;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AccessList stores salted urls (code from miniPassword.java from Security book)
 */
public class AccessController {

    private List<Object> accessList = new ArrayList<Object>(Arrays.asList(
            "128.60.25.3",
            "127.128.32.5",
            "61.110.4.11"
    ));
    public static final int KEY_SIZE = 16; // 128 bits

    /**
     * Gets url, encode it and then saves it a list.
     *
     * @param address
     * @return true if url was added to the list
     */
    public boolean addUrl(Object address) throws Exception {
        // 1. encrypt url

        // 2. add url to AccessList
        if (accessList.size() == 0 || !accessList.contains(address)) {
            accessList.add(address);
            return true;
        }

        return false; // the url wasn't added or was already added in the list
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
     * Extracts a packet and parses it to get the Address and Payload.
     * Assumes the packet format is a AccessList Address (16 characters) followed by the Packet Payload (64 characters)
     * example: ip.ljust(16) + ''.join(random.choice(string.ascii_letters) for _ in range(64))
     *
     * @param packet
     */
    public boolean addressExtractor(Object packet) throws Exception {
        return addUrl(packet);
    }

    /** returns the SHA-256 hash of the provided preimage as a String */
    private byte[] encodeUrl(String url) throws Exception {
        MessageDigest md = null;
        md = MessageDigest.getInstance("SHA-256");
        md.update(url.getBytes("UTF-8"));
        byte raw[] = md.digest();
        return Base64.encodeBase64(raw);
    } }
