package us.stad.entity;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.github.jgonian.ipmath.Ipv4;
import com.github.jgonian.ipmath.Ipv4Range;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

public class CidrGroup {

    private static Map<String, CidrGroup> CACHE = new HashMap<>();
    private static int CACHE_HIT = 0;

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
                CidrGroup.CACHE_HIT++;
                return true;
            }
        }
        return false;
    }

    public static int getCacheHit() {
        return CACHE_HIT;
    }

    public static CidrGroup getMatchingCidrGroup(String address, String port) {
        for (CidrGroup group : CACHE.values()) {
            if (group.addressInCidrRange(address) && group.port.equalsIgnoreCase(port)) {
                return group;
            }
        }
        return null;
    }

    public static void dumpCache(final Writer writer) throws IOException {
        CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader("cidr_range", "port", "inbound", "outbound", "netname", "organization", "inbound_ip", "outbound_ip").build();
        try (CSVPrinter csvPrinter = new CSVPrinter(writer, csvFormat)) {
            for (CidrGroup group : CACHE.values()) {
                csvPrinter.printRecord(
                    Arrays.toString(group.cidrRanges.toArray()),
                    group.port,
                    group.inboundList.isEmpty() ? "false" : "true",
                    group.outboundList.isEmpty() ? "false" : "true",
                    group.netname,
                    group.organization,
                    Arrays.toString(group.inboundList.toArray()),
                    Arrays.toString(group.outboundList.toArray()));
                csvPrinter.flush();
            }
        }
    }

}
