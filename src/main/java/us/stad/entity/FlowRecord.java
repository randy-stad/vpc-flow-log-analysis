package us.stad.entity;

public class FlowRecord {

    private WhoisRecord whoisRecord;
    private String sourceAddress;
    private String destinationAddress;
    private String sourcePort;
    private String destinationPort;
    private String protocol;

    public FlowRecord(String sourceAddress, String desinationAddress, String sourcePort, String destinationPort,
            String protocol, WhoisRecord whoisRecord) {
        this.sourceAddress = sourceAddress;
        this.destinationAddress = desinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.whoisRecord = whoisRecord;
    }

    @Override
    public String toString() {
        return this.whoisRecord.getCidr() + "," + this.sourceAddress +  "," + this.sourcePort + "," + this.protocol + "," + this.whoisRecord.getOrganization();
    }

}
