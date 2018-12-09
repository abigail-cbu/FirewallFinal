package AccessList;

import java.util.ArrayList;
import java.util.List;

/**
 * Description: logs rejected packages,
 * indicating a hacker that is trying to breach the firewall
 */
public class Logger {

    public List<Object> accessList = new ArrayList<Object>();

    /**
     * Adds package to list
     * @param packageList
     */
    public void logReject(Object packageList) {
        accessList.add(packageList);
    }

    /**
     * Display a list of packages that were rejected
     */
    public void displayRejects() {
        System.out.println("The following are packages that have been rejected:");
        for(Object reject : accessList) {
            System.out.println(reject);
        }
    }

}
