package Firewall;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Description: logs rejected packets,
 * indicating a hacker that is trying to breach the firewall
 */
public class Logger {

    // VARIABLES
    // static list that is maintained throughout the project
    private static List<String> rejectedList = new ArrayList<String>();
    private final int IP_MAX_LENGTH = 16;

    // PUBLIC METHODS
    /**
     * Adds package to list
     *
     * @param packet
     */
    public void logReject(Object packet) {
        rejectedList.add(StringUtils.substring(packet.toString(), 0, IP_MAX_LENGTH));
    }

    /**
     * Display a list of packages that were rejected
     */
    public String displayRejects() {
        System.out.println("The following are packages that have been rejected:");
        for (Object reject : rejectedList) {
            System.out.println(reject);
        }

        return StringUtils.join(", ", rejectedList);
    }

}
