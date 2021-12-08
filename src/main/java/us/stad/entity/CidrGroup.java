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
import com.github.jgonian.ipmath.Ipv6;
import com.github.jgonian.ipmath.Ipv6Range;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

public class CidrGroup {

    private static Map<String, CidrGroup> CACHE = new HashMap<>();
    private static int CACHE_HIT = 0;

    List<Ipv4Range> ipv4Ranges = new ArrayList<>();
    List<Ipv6Range> ipv6Ranges = new ArrayList<>();
    String organization;
    String netname;
    String port;
    String protocol;
    Set<String> inboundList = new HashSet<>();
    Set<String> outboundList = new HashSet<>();

    public CidrGroup(WhoisRecord whois, String port, String protocol) {
        if (whois.getCidr() != null) {
            final String[] range = whois.getCidr().split(",\\s*");
            for (String i : range) {
                if (i.contains(":")) {
                    this.ipv6Ranges.add(Ipv6Range.parse(i));
                } else {
                    this.ipv4Ranges.add(Ipv4Range.parse(i));
                }
            }
        } else if (whois.getInetnum() != null) {
            final String[] range = whois.getInetnum().split("-");
            if (range.length == 2) {
                String start = range[0].trim();
                String end = range[1].trim();
                if (start.contains(":")) {
                    this.ipv6Ranges.add(Ipv6Range.from(start).to(end));
                } else {
                    this.ipv4Ranges.add(Ipv4Range.from(start).to(end));
                }
            }
        }
        this.organization = whois.getOrganization();
        this.netname = whois.getNetname();
        this.port = port;
        this.protocol = protocol;
        CACHE.put(whois.getCidr(), this);
    }

    public void addInboundAddress(final String address) {
        this.inboundList.add(address);
    }

    public void addOutboundAddress(final String address) {
        this.outboundList.add(address);
    }

    public boolean addressInCidrRange(final String address) {
        if (address.contains(":")) {
            final Ipv6 ipv6 = Ipv6.parse(address);
            for (Ipv6Range i : this.ipv6Ranges) {
                if (i.contains(ipv6)) {
                    CidrGroup.CACHE_HIT++;
                    return true;
                }
            }
        } else {
            final Ipv4 ipv4 = Ipv4.parse(address);
            for (Ipv4Range i : this.ipv4Ranges) {
                if (i.contains(ipv4)) {
                    CidrGroup.CACHE_HIT++;
                    return true;
                }
            }
        }
        return false;
    }

    public static int getCacheHit() {
        return CACHE_HIT;
    }

    public static CidrGroup getMatchingCidrGroup(String address, String port, String protocol) {
        for (CidrGroup group : CACHE.values()) {
            if (group.addressInCidrRange(address) && group.port.equalsIgnoreCase(port)
                    && group.protocol.equalsIgnoreCase(protocol)) {
                return group;
            }
        }
        return null;
    }

    public static void dumpCache(final Writer writer) throws IOException {
        CSVFormat csvFormat = CSVFormat.DEFAULT.builder().setHeader("cidr_range", "port", "protocol", "inbound",
                "outbound", "netname", "organization", "inbound_ip", "outbound_ip").build();
        try (CSVPrinter csvPrinter = new CSVPrinter(writer, csvFormat)) {
            for (CidrGroup group : CACHE.values()) {
                csvPrinter.printRecord(
                        Arrays.toString(group.ipv4Ranges.toArray()).replace('[', '{').replace(']', '}'),
                        group.port,
                        group.protocol,
                        group.inboundList.isEmpty() ? "false" : "true",
                        group.outboundList.isEmpty() ? "false" : "true",
                        group.netname,
                        group.organization,
                        Arrays.toString(group.inboundList.toArray()).replace('[', '{').replace(']', '}'),
                        Arrays.toString(group.outboundList.toArray()).replace('[', '{').replace(']', '}'));
                csvPrinter.flush();
            }
        }
    }

}
