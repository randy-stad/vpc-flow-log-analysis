package us.stad;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;

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

/**
 * VPC flow log analysis tool.
 */
public class App {

    static final SessionFactory SESSION_FACTORY = new Configuration().configure().buildSessionFactory();

    public static void main(String[] args) {

        CommandLine line = null;
        final Options options = buildOptions();
        try {
            CommandLineParser parser = new DefaultParser();
            line = parser.parse(options, args);
        } catch (ParseException exp) {
            System.err.println("Parsing failed: " + exp.getMessage());
            System.exit(1);
        }

        if (line.hasOption("h")) {
            new HelpFormatter().printHelp("vpc-flow-log-analysis", options);
            System.exit(0);
        }

        if (line.hasOption("s")) {
            int maxLineCount = Integer.MAX_VALUE;
            if (line.hasOption("l")) {
                maxLineCount = Integer.parseInt(line.getOptionValue("l"));
            }
            processSourceFile(line.getOptionValue("s"), maxLineCount);
            System.out.println("WHOIS cache hit: " + whoisCacheHit + " miss: " + whoisCacheMiss);
            System.out.println("CIDR cache hit: " + CidrGroup.cacheHit);
            CidrGroup.dumpCache();
        } else {
            for (String address : line.getArgList()) {
                System.out.println(getWhoisRecord(address));
            }
        }

    }

    static final int SOURCE_ADDRESS = 0;
    static final int DESTINATION_ADDRESS = 1;
    static final int SOURCE_PORT = 2;
    static final int DESTINATION_PORT = 3;
    static final int PROTOCOL = 4;

    private static void processSourceFile(final String filename, final int maxLineCount) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineCount = 0;
            while ((line = reader.readLine().trim()) != null) {
                lineCount++;
                if (lineCount > maxLineCount) {
                    return;
                }
                if (Character.isDigit(line.charAt(0))) {
                    String[] entries = line.split("\\s*,\\s*");
                    final boolean sourceUnroutable = addressIsUnroutable(entries[SOURCE_ADDRESS]);
                    final boolean destUnroutable = addressIsUnroutable(entries[DESTINATION_ADDRESS]);
                    if (sourceUnroutable && !destUnroutable) {
                        // outbound
                        CidrGroup cidr = CidrGroup.getMatchingCidrGroup(entries[DESTINATION_ADDRESS], entries[DESTINATION_PORT]);
                        if (cidr != null) {
                            cidr.addOutboundAddress(entries[DESTINATION_ADDRESS]);
                        } else {
                            cidr = new CidrGroup(getWhoisRecord(entries[DESTINATION_ADDRESS]), entries[DESTINATION_PORT]);
                            cidr.addOutboundAddress(entries[DESTINATION_ADDRESS]);
                        }
                    } else if (!sourceUnroutable && destUnroutable) {
                        // inbound
                        CidrGroup cidr = CidrGroup.getMatchingCidrGroup(entries[SOURCE_ADDRESS], entries[SOURCE_PORT]);
                        if (cidr != null) {
                            cidr.addOutboundAddress(entries[SOURCE_ADDRESS]);
                        } else {
                            cidr = new CidrGroup(getWhoisRecord(entries[SOURCE_ADDRESS]), entries[SOURCE_PORT]);
                            cidr.addInboundAddress(entries[SOURCE_ADDRESS]);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static final Ipv4Range RANGE10 = Ipv4Range.parse("10.0.0.0/8");
    static final Ipv4Range RANGE172 = Ipv4Range.parse("172.16.0.0/12");
    static final Ipv4Range RANGE192 = Ipv4Range.parse("192.168.0.0/16");

    private static boolean addressIsUnroutable(final String address) {
        final Ipv4 ipv4 = Ipv4.parse(address);
        return RANGE10.contains(ipv4) || RANGE172.contains(ipv4) || RANGE192.contains(ipv4);
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

        try (Session session = SESSION_FACTORY.getCurrentSession()) {
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

        try (Session session = SESSION_FACTORY.getCurrentSession()) {
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
        options.addOption("l", "lines", true, "process a maximum number of specified lines in input file");
        options.addOption("s", "source", true,
                "csv file to parse with format SourceAddress, DestinationAddress, SourcePort, DestinationPort, Protocal");
        options.addOption("h", "help", false, "print this message");

        return options;

    }
}
