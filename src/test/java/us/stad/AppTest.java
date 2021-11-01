package us.stad;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import us.stad.entity.CidrGroup;
import us.stad.entity.WhoisRecord;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AppTest.class);
    }

    /**
     * CIDR group tests.
     */
    public void testCidrGroup() {
        WhoisRecord whois = new WhoisRecord("52.94.228.178");
        whois.setCidr("52.88.0.0/13, 52.84.0.0/14");
        whois.setOrganization("organization");
        whois.setNetname("netname");

        CidrGroup cidrGroup = new CidrGroup(whois, "443", "TCP");

        assertTrue("IP in range", cidrGroup.addressInCidrRange("52.94.228.178"));
        assertFalse("IP not in range", cidrGroup.addressInCidrRange("192.168.0.1"));
        
        assertNotNull(CidrGroup.getMatchingCidrGroup("52.94.228.178", "443", "TCP"));
        assertNull(CidrGroup.getMatchingCidrGroup("52.94.228.178", "443", "UCP"));
        assertNull(CidrGroup.getMatchingCidrGroup("52.94.228.178", "80", "TCP"));
        assertNull(CidrGroup.getMatchingCidrGroup("192.168.0.1", "443", "TCP"));
        assertNull(CidrGroup.getMatchingCidrGroup("192.168.0.1", "80", "TCP"));

        assertTrue(true);
    }
}
