# vpc-flow-log-analysis

Analyze AWS VPC flow logs in CSV format.

## Flow Log CSV format

As flow logs from AWS are very verbose, this utility uses an abbreviated CSV format with the following fields:

```
    SOURCE_ADDRESS
    DESTINATION_ADDRESS
    SOURCE_PORT
    DESTINATION_PORT
    PROTOCOL
```

A simple script can transform your logs to this input format.

## Build and Package

Using maven and a modern Java runtime build and package with:

```
    mvn clean package
```

This will build a fat jar in the target directory.

## Run

There is help available:

```
    java -jar target/vpc-flow-log-analysis-1.0-SNAPSHOT.jar --help
```

The script will use the ```whois``` command to perform the lookup. The script has been tested using the macOS Monterey version so your mileage may vary.

Note that the script will create a ```cache``` directory with an H2 database of ```whois``` lookup information. Remove the cache if you want to rebuild with the latest ```whois``` information but realize that lookup will take longer as the cache is recreated.
