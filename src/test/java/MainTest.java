import AccessList.AccessController;
import org.junit.jupiter.api.Test;

/**
 * Description: MainTest contains JUnits tests that will test the
 * AccessList package
 * and make sure that the project fulfills the requirements stated in the README.md file
 */
public class MainTest {

    @Test
    public void TestGoodURLs() {
        AccessController ac = new AccessController();

        ac.addressExtractor("128.60.25.3");
    }
}
