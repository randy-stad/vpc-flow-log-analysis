package us.stad.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "whois_cache")
public class WhoisRecord implements Serializable {

    @Id
    private String address;
    private String cidr;
    private String inetnum;
    private String organization;
    private String netname;

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getCidr() {
        return cidr;
    }

    public void setCidr(String cidr) {
        this.cidr = cidr;
    }

    public String getInetnum() {
        return inetnum;
    }

    public void setInetnum(String inetnum) {
        this.inetnum = inetnum;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getNetname() {
        return netname;
    }

    public void setNetname(String netname) {
        this.netname = netname;
    }

    public WhoisRecord() {
        this("");
    }

    public WhoisRecord(final String address) {
        this.setAddress(address);
    }

    public void parseWhoisLine(final String line) {
        if (line.toLowerCase().startsWith("cidr:")) {
            this.cidr = line.substring(line.indexOf(':') + 1).trim();
        } else if (line.toLowerCase().startsWith("organization:")) {
            this.organization = line.substring(line.indexOf(':') + 1).trim();
        } else if (line.toLowerCase().startsWith("inetnum:")) {
            this.inetnum = line.substring(line.indexOf(':') + 1).trim();
        } else if (line.toLowerCase().startsWith("netname:")) {
            this.netname = line.substring(line.indexOf(':') + 1).trim();
        }
    }

}