package us.stad.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.github.jgonian.ipmath.Ipv4;
import com.github.jgonian.ipmath.Ipv4Range;

public class CidrGroup {

    private static Map<String, CidrGroup> CACHE = new HashMap<>();
    public static int cacheHit = 0;

    List<Ipv4Range> cidrRanges = new ArrayList<>();
    String organization;
    String netname;
    String port;
    Set<String> inboundList = new HashSet<>();
    Set<String> outboundList = new HashSet<>();

    public CidrGroup(WhoisRecord whois, String port) {
        if (whois.getCidr() != null) {
            final String[] range = whois.getCidr().split(",\\s*");
            for (String i : range) {
                this.cidrRanges.add(Ipv4Range.parse(i));
            }
        }
        this.organization = whois.getOrganization();
        this.netname = whois.getNetname();
        this.port = port;
        CACHE.put(whois.getCidr(), this);
    }

    public void addInboundAddress(final String address) {
        this.inboundList.add(address);
    }

    public void addOutboundAddress(final String address) {
        this.outboundList.add(address);
    }

    public boolean addressInCidrRange(final String address) {
        final Ipv4 ipv4 = Ipv4.parse(address);
        for (Ipv4Range i : this.cidrRanges) {
            if (i.contains(ipv4)) {
                cacheHit++;
                return true;
            }
        }
        return false;
    }

    public static CidrGroup getMatchingCidrGroup(String address, String port) {
        for (CidrGroup group : CACHE.values()) {
            if (group.addressInCidrRange(address) && group.port.equalsIgnoreCase(port)) {
                return group;
            }
        }
        return null;
    }

    public static void dumpCache() {
        for (CidrGroup group : CACHE.values()) {
            System.out.println(group);
        }
    }

}
