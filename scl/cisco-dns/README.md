# syslogng-cisco-dns

Syslogng drivers for Cisco DNS logs in S3 buckets

## Purpose

This is a python syslogng.LogFetcher implementation designed to fetch events from [Cisco DNS S3 buckets](https://docs.umbrella.com/deployment-umbrella/docs/cisco-managed-s3-bucket).

## Dependencies

This driver requires the Python boto3 module to be available which is not included with syslog-ng PE. There are several ways to access it including:

Install the required module directly into the syslog-ng PE installation

    /opt/syslog-ng/bin/python3 -m pip install boto3

Use the base OS Python modules for syslog-ng by modifying plugin.conf for the correct local path:

    sys.path.append("/usr/lib/python3.8/site-packages/")

To fully validate SSL certificates it may also be necessary to install the certifi module and upgrade the cacerts

    /opt/syslog-ng/bin/python3 -m pip install --upgrade certifi

## Installation

To install and configure the Cisco DNS driver, create a new SCL directory for the driver and copy cisco-dns.py and plugin.conf to it:

    /opt/syslog-ng/share/syslog-ng/include/scl/cisco-dns/

## Components

### cisco-dns.py

This is the syslogng.LogFetcher implementation which can be configured as a standalone source in syslog-ng. To utilize the driver, the following steps are needed:
1. Create a new SCL directory named cisco-dns (e.g., /opt/syslog-ng/share/syslog-ng/include/scl/cisco-dns/)
2. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/cisco-dns/plugin.conf
3. Save cisco-dns.py to /opt/syslog-ng/share/syslog-ng/include/scl/cisco-dns/cisco-dns.py
4. Create a new syslog-ng source with the required parameters

To configure the source, certain parameters are availble:

    source s_cisco-dns {
        python-fetcher(
            class("cisco-dns.Dns")
            options(
                "aws_access_key_id","<AWS Access Key for S3 Access>"
                "aws_secret_access_key","<Base64 encode AWS Secret Access Key for S3 Access>"
                "bucket","<S3 Bucket for Log Archives>"
                "backfill_minutes","<Minutes Past Last Fetch to Check>" # optional - defaults to 5
                "disk_buffer","<Location to store in-memory events during >" # optional but highly recommended
                "log_level","<DEBUG|INFO|WARN|ERROR>" # optional - defaults to INFO
                "ssl_verify","<true|false|/path/to/CA.pem>" # optional - defaults to requiring trusted certificate
                "proxy","<URL for proxy server>" # optional - defaults to direct https connections
                "state_file","<Path to file for maintaining state>" # optional but highly recommended
                "deque_length","<Number of archives to store internally for tracking state>" # optional - defaults to 10000
                "state_size","<Number of archives to store in state file for tracking state between restarts>" # optional - defaults to 10000
                "buffer_size","<Number or messages to batch up from uncompressed archives before starting to process them>" # optional - defaults to 10000000
                "blocklist","<file path to list of organizations to not process archives from>" # optional - defaults to processing all archives found in s3
            )
            flags(no-parse)
            fetch-no-data-delay(<seconds to wait before attempting a fetch after no results are returned>)
        );
    };

Here are sample values as a reference:

    source s_cisco-dns {
        python-fetcher(
            class("cisco-dns.Dns")
            options(
                "aws_access_key_id","AAAAAAAAAAAAAAAAAAAAA"
                "aws_secret_access_key" "AAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                "bucket" "myorg-cisco-dns"
                "backfill_minutes" "10" # optional - defaults to 5
                "disk_buffer" "/var/run/cisco-dns.buffer" # optional
                "log_level" "DEBUG" # optional - defaults to INFO
                "ssl_verify","FALSE" # optional - defaults to requiring trusted SSL certificate
                "proxy","http://my.proxy.com" # optional - defaults to direct https connections
                "state_file","/opt/syslog-ng/var/cisco-dns.state" # optional but recommended
                "deque_length","1000" # optional - defaults to 10000
                "state_size","100" # optional - defaults to 10000
                "buffer_size","10000" # optional - defaults to 10000000
                "blocklist","/opt/syslog-ng/etc/s3-blocklist.txt" # optional - defaults to processing all archives found in s3
            )
            flags(no-parse)
            fetch-no-data-delay(60)
        );
    };


### Driver options

aws_access_key_id - The AWS access key for an account with access to the S3 bucket

aws_secret_access_key - The AWS secret access key for an account with access to the S3 bucket (base64 encoded)

bucket - The S3 bucket Cisco DNS logs can be found in

backfill_minutes - How many minutes past the last fetch to start the new fetch for. This extra buffer is to compensate for any latency in S3 where new objects aren't immediately visible 

disk_buffer - If the driver shuts down before all logs have been returned by the driver, the remaining logs will be saved here and loaded when the driver is started back up

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng (optional, defaults to INFO)

ssl_verify - Whether or not to require trusted certificates (true or false) (optional - defaults to True)

proxy - URL of proxy server for outbound access (optional)

state_file - File path to use for tracking processed DNS log archives so they're not accidentally processed twice

deque_length - Number of archive names to be stored in the internal deque for tracking which archives have been processed already (optional - defaults to 10000)

state_size - Number of archive names to be written to state file for syslog-ng reload/restart operations (ptional - defaults to 1000)

buffer_size - Number of messages to extract from archives in a single pass before starting to process them (optional - defaults to 1000000)

blocklist - A filepath to a list or organizations that the driver should ignore when processing archives from s3 (optional - default behavior is to process all archives and paths)