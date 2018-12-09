package AccessList;

import java.util.ArrayList;
import java.util.List;

/**
 * Description: logs rejected packets,
 * indicating a hacker that is trying to breach the firewall
 */
public class Logger {

    private List<Object> rejectedList = new ArrayList<Object>();

    /**
     * Adds package to list
     * @param packet
     */
    public void logReject(Object packet) {
        rejectedList.add(packet);
    }

    /**
     * Display a list of packages that were rejected
     */
    public void displayRejects() {
        System.out.println("The following are packages that have been rejected:");
        for(Object reject : rejectedList) {
            System.out.println(reject);
        }
    }

}
