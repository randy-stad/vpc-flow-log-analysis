package us.stad;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.text.NumberFormat;
import java.util.Locale;

import com.github.jgonian.ipmath.Ipv4;
import com.github.jgonian.ipmath.Ipv4Range;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

import us.stad.entity.CidrGroup;
import us.stad.entity.WhoisRecord;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * VPC flow log analysis tool.
 */
public class VpcFlowLogAnalysis {

    private static final Log LOG = LogFactory.getLog(VpcFlowLogAnalysis.class);
    private static final SessionFactory SESSION_FACTORY = new Configuration().configure().buildSessionFactory();

    public static void main(String[] args) {

        CommandLine line = null;
        final Options options = buildOptions();
        try {
            CommandLineParser parser = new DefaultParser();
            line = parser.parse(options, args);
        } catch (ParseException exp) {
            LOG.error("Parsing failed", exp);
            System.exit(1);
        }

        if (line.hasOption("h")) {
            new HelpFormatter().printHelp("vpc-flow-log-analysis", options);
            System.exit(0);
        }

        if (line.hasOption("s") && !line.hasOption("o")) {
            new HelpFormatter().printHelp("vpc-flow-log-analysis", options);
            System.exit(1);
        }

        if (line.hasOption("s")) {
            long fromLine = 0;
            long toLine = Long.MAX_VALUE;
            if (line.hasOption("f")) {
                fromLine = Long.parseLong(line.getOptionValue("f"));
            }
            if (line.hasOption("t")) {
                toLine = Long.parseLong(line.getOptionValue("t"));
            }
            processSourceFile(line.getOptionValue("s"), fromLine, toLine);
            LOG.info("WHOIS cache hit: " + whoisCacheHit + " miss: " + whoisCacheMiss);
            LOG.info("CIDR cache hit: " + CidrGroup.getCacheHit());

            try (FileWriter writer = new FileWriter(line.getOptionValue("o"))) {
                CidrGroup.dumpCache(writer);
            } catch (Exception e) {
                LOG.error("CSV dump failed", e);
                System.exit(1);
            }
        } else {
            for (String address : line.getArgList()) {
                LOG.info(getWhoisRecord(address));
            }
        }

    }

    static final int SOURCE_ADDRESS = 0;
    static final int DESTINATION_ADDRESS = 1;
    static final int SOURCE_PORT = 2;
    static final int DESTINATION_PORT = 3;
    static final int PROTOCOL = 4;

    private static void processSourceFile(final String filename, final long from, final long to) {
        LOG.info("process " + filename + " from " + from + " to " + to);
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            long lineNumber = 0;
            long processedCount = 0;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                lineNumber++;
                if (lineNumber >= to) {
                    return;
                }
                if (lineNumber > from) {
                    processedCount++;
                    if (processedCount % 100000 == 0) {
                        LOG.info("processed " + NumberFormat.getNumberInstance(Locale.US).format(processedCount) + " lines");
                    }
                    if (Character.isDigit(line.charAt(0))) {
                        String[] entries = line.split("\\s*,\\s*");
                        final boolean sourcePrivate = addressIsPrivate(entries[SOURCE_ADDRESS]);
                        final boolean destPrivate = addressIsPrivate(entries[DESTINATION_ADDRESS]);
                        if (sourcePrivate && !destPrivate) {
                            // outbound
                            CidrGroup cidr = CidrGroup.getMatchingCidrGroup(entries[DESTINATION_ADDRESS],
                                    entries[DESTINATION_PORT], entries[PROTOCOL]);
                            if (cidr != null) {
                                cidr.addOutboundAddress(entries[DESTINATION_ADDRESS]);
                            } else {
                                cidr = new CidrGroup(getWhoisRecord(entries[DESTINATION_ADDRESS]),
                                        entries[DESTINATION_PORT], entries[PROTOCOL]);
                                cidr.addOutboundAddress(entries[DESTINATION_ADDRESS]);
                            }
                        } else if (!sourcePrivate && destPrivate) {
                            // inbound
                            CidrGroup cidr = CidrGroup.getMatchingCidrGroup(entries[SOURCE_ADDRESS],
                                    entries[SOURCE_PORT], entries[PROTOCOL]);
                            if (cidr != null) {
                                cidr.addInboundAddress(entries[SOURCE_ADDRESS]);
                            } else {
                                cidr = new CidrGroup(getWhoisRecord(entries[SOURCE_ADDRESS]), entries[SOURCE_PORT],
                                        entries[PROTOCOL]);
                                cidr.addInboundAddress(entries[SOURCE_ADDRESS]);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // list of private IPs, should probably be external but, meh
    
    static final Ipv4Range[] PRIVATE_RANGE = {
        Ipv4Range.parse("10.0.0.0/8"),
        Ipv4Range.parse("100.0.0.0/16"),
        Ipv4Range.parse("172.16.0.0/12"),
        Ipv4Range.parse("192.168.0.0/16")
    };

    private static boolean addressIsPrivate(final String address) {
        // assume all IPv6 are public and avoid issues
        if (address.contains(":")) {
            return false;
        }
        final Ipv4 ipv4 = Ipv4.parse(address);
        for (Ipv4Range range : PRIVATE_RANGE) {
            if (range.contains(ipv4)) {
                return true;
            }
        }
        return false;
    }

    private static int whoisCacheHit = 0;
    private static int whoisCacheMiss = 0;

    /**
     * Call the command line version of whois on the system to get details about the
     * specified IP address.
     * 
     * @param address IP address
     */
    private static WhoisRecord getWhoisRecord(final String address) {

        WhoisRecord result = null;

        // load from database

        try (Session session = SESSION_FACTORY.openSession()) {
            session.getTransaction().begin();
            result = session.get(WhoisRecord.class, address);
            session.getTransaction().commit();
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (result != null) {
            whoisCacheHit++;
            return result;
        }

        whoisCacheMiss++;
        result = new WhoisRecord(address);
        String command = "whois " + address;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec(command).getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.parseWhoisLine(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // persist to database

        try (Session session = SESSION_FACTORY.openSession()) {
            session.getTransaction().begin();
            session.persist(result);
            session.getTransaction().commit();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    private static Options buildOptions() {

        Options options = new Options();
        options.addOption("f", "from", true, "process from this line in the source file");
        options.addOption("t", "to", true, "process to this line in the source file");
        options.addOption("o", "output", true, "output file (required if source specified)");
        options.addOption("s", "source", true,
                "csv file to parse with format SourceAddress, DestinationAddress, SourcePort, DestinationPort, Protocol");
        options.addOption("h", "help", false, "print this message");

        return options;

    }
}
