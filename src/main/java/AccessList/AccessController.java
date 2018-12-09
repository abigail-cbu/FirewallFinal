package AccessList;

import java.util.ArrayList;
import java.util.List;

public class AccessController {

    public List<Object> accessList = new ArrayList<Object>();

    /**
     * Adds url to saved list.
     *
     * @param packageList
     * @return true if url was added to the list
     */
    public boolean addUrl(Object packageList) {
        if (accessList.size() == 0 || !accessList.contains(packageList)) {
            accessList.add(packageList);
            return true;
        }

        return false; // the url wasn't added or was already added in the list
    }

    /**
     * Checks if url has access
     * @param url
     * @return true if url is within the access list
     */
    public boolean hasAccess(String url) {
        if (accessList.contains(url)) {
            return true;
        }

        return false;
    }
}
