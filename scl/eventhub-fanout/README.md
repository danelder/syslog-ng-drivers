# syslogng-eventhub

## Purpose

Using Azure Event Hubs as a syslog-ng destination is possible by using the http driver and setting the necessary parameters. A simple overview is available [here](https://www.syslog-ng.com/community/b/blog/posts/feeding-events-with-syslog-ng-pe-to-azure-event-hub-and-google-pub-sub). The purpose of this utility is to automate the creation of Azure Event Hub destinations and listening sources at runtime using the syslog-ng [confgen](https://support.oneidentity.com/technical-documents/syslog-ng-premium-edition/7.0.32/administration-guide/23#TOPIC-1925395) functionality.

## Components

### gen-http.py

This is the confgen script used to dynamically create Azure Event Hub destinations and listening sources based off a configuration file. It should be ideally copied to the standard SCL location in it's own directory. To utilize the syslogng-eventhub destination driver, the following steps are needed:
1. Install the netifaces Python module (e.g., python3-netifcates if it's not already installed)
2. Create new SCL directory named eventhub (e.g., /opt/syslog-ng/share/syslog-ng/include/scl/eventhub)
3. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/eventhub/plugin.conf
4. Save gen-http.py to /opt/syslog-ng/share/syslog-ng/include/scl/eventhub/gen-http.py
5. Create new eventhub configuration file (e.g., /opt/syslog-ng/etc/eventhub.ini)
6. Create a new syslog-ng configuration file with the required parameters

The eventhub configuration file should have 3 sections:
1. [Countries] - This section should include a 2 letter list of country names and the number of http workers each country should use
2. [Templates] - This section should include any output templates that will be used
3. [Individual Source Names] - One or more source definitions that can include:
   1. A port number for incoming connections (mandatory)
   2. A template to use for outgoing messages (must match a definition in the [Templates] section)
   3. A filter to use for messages (defined outside of the eventhub configuration)
   4. A multiplier to use for the workers assigned to a destination to optimize performance (for higher or lower volume destinations)
   5. Whether to create a local log (file) for the destination (useful for debug purposes but disabled in container environments) as either true or false (local_log)
   6. An address (or comma separated list of interfaces) to bind to. The first interface in the list which resolves to an addres (or the first address in the list) will be used if specified and if none resolve the global address will be used (0.0.0.0 by default)
   7. An comma separated list of an additional syslog-ng destination(s) (which must be defined elsewhere in your syslog-ng configuration) that logs for this configuration should be sent to
   8. Syslog-ng rewrite rule(s) (which must be defined elsewhere in your syslog-ng configuration) which should be applied to logs for this configuration

As an example, here are reference values for eventhub.ini:

    [Countries]
    US=5
    EU=2
    AS=2
    UK=2

    [Templates]
    default="${MSGHDR} ${ISODATE} ${HOST} ${MESSAGE}"
    message="${MESSAGE}"

    [sl-aix]
    port=7024 
    template=default
    filters=f_sample1,f_sample2
    workers=1.5
    address=eth0,eth0:1,1.2.3.4
    destinations=d_remote_1

    [sl-ios]
    port=7025
    template=message
	local_log=true
    rewrites=r_rule1,r_rule2

    [sl-lnx]
    port=7026
    workers=2
    destinations=d_remote_2,d_remote_3

    [sl-pan]
    port=7027

Each log pipeline section must include the name in brackets and a port. A template value may also be specified (the default template will be used if none is defined). One or more filters may also be defined which will immediately follow the source in the resulting syslog-ng configuration.

For the syslog-ng configure file, both the sources and destinations are created through a single decleration for eventhub which requires at least the following configuration options:

    eventhub(
    	url() # URL to Azure Event Hubs
    	headers() # Authorization headers to past for authentication
    	auth_token() # Filepath with Azure auth token in it
    	ini() # Filepath to driver configuration ini
    	keyfile() # Filepath to TLS key used for syslog listener
    	certfile() # Filepath to TLS cert used for syslog listener
    );

Optional parameters can also be specified to improve performance or alter behavior:

    batch_lines() # (https://support.oneidentity.com/technical-documents/doc1925775) - defaults to 1000
    batch_bytes() # (https://support.oneidentity.com/technical-documents/doc1925773) - defaults to 1023kb
    batch_timeout() # (https://support.oneidentity.com/technical-documents/doc1925776) - defaults to 10000
    disk_buf() # (https://support.oneidentity.com/technical-documents/doc1925781) - defaults to 10485760
    disk_dir() # (https://support.oneidentity.com/technical-documents/doc1925781) - defaults to /tmp
    mem_buf() # (https://support.oneidentity.com/technical-documents/doc1925781) - defaults to 10000
    fetch_limit() # (https://support.oneidentity.com/technical-documents/doc1925846) - defaults to 10000
    rcvbuf() # (https://support.oneidentity.com/technical-documents/doc1925861) - defaults to 20971520
    address() # Specific address (or comma separated list of interfaces/addresses) to listen on for incoming syslog traffic. When specifying an interface(s), the first in the list which resolves to an address will be used - defaults to 0.0.0.0
    tls_verify() # Whether to validate the Azure Event Hub certificate or not - defaults to no
    local_log_path() # If set and individual source has local_log=true set, will create a local log in a new directory named after the source as an additional destination (useful for debugging)

As an example, here is a sample configuration: 

    eventhub(
    	url('https://xxxxxxx.servicebus.windows.net')
    	batch_lines(1000)
    	batch_bytes(1023kb)
    	batch_timeout(10000)
    	disk_buf(2097152)
    	mem_buf(50000)
    	fetch_limit(100000)
    	rcvbuf(67108864)
    	headers("Authorization: SharedAccessSignature sr=xxxxx.servicebus.windows.net&sig=AUTH_TOKEN&skn=rootSend-syslogNG","Content-Type: application/json","Host: xxxxx.servicebus.windows.net","Country:")
    	tls_verify('no')
    	auth_token('/opt/syslog-ng/etc/eventhub-auth')	
    	ini('/opt/syslog-ng/etc/eventhub.ini')
    	address('eth0,1.2.3.4')
    	disk_dir('/tmp')
    	keyfile('/opt/syslog-ng/etc/cert.d/delder.theelderfamily.org.crt')
    	certfile('/opt/syslog-ng/etc/cert.d/delder.theelderfamily.org.crt')
    	local_log_path('/tmp')
    );

### Driver options

url - The URL to Azure Event Hub

batch_lines - [Syslog-ng batch-lines() option](https://support.oneidentity.com/technical-documents/doc1925775)  (defaults to 1000)

batch_bytes - [Syslog-ng batch-bytes() option](https://support.oneidentity.com/technical-documents/doc1925773)  (defaults to 1023kb). Be careful to stay within [Azure Event Hubs quotas](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-quotas)

batch_timeout - [Syslog-ng batch-timeout() option](https://support.oneidentity.com/technical-documents/doc1925776) (defaults to 10000)

disk_buf - [Syslog-ng disk-buf-size() option](https://support.oneidentity.com/technical-documents/doc1925781) (defaults to 10485760)

disk_dir - [Syslog-ng dir() option](https://support.oneidentity.com/technical-documents/doc1925781) (defaults to /tmp/<name of destination>)

mem_buf - [Syslog-ng mem-buf-length() option](https://support.oneidentity.com/technical-documents/doc1925781) (defaults to 10000)

fetch_limit - [Syslog-ng fetch-limit() option](https://support.oneidentity.com/technical-documents/doc1925846) (defaults to 10000)

rcvbuf - [Syslog-ng so-rcvbuf() option](https://support.oneidentity.com/technical-documents/doc1925861) (defaults to 20971520). More tuning details [available](https://support.oneidentity.com/syslog-ng-premium-edition/kb/4368987/how-to-configure-so-rcvbuf-4368987)

address - Specific address to listen on for incoming syslog traffic (defaults to 0.0.0.0)

headers - [Syslog-ng headers() option](https://support.oneidentity.com/technical-documents/syslog-ng-premium-edition/7.0.31/administration-guide/47#TOPIC-1863006) Authorization headers to pass for authentication

auth_token - Filepath with Azure auth token in it which is used for http headers for authorization

ini - Filepath to driver configuration ini

keyfile - Filepath to TLS key used for syslog listener

certfile - Filepath to TLS cert used for syslog listener

tls_verify - Whether to validate the Azure Event Hub certificate or not (defaults to no)

local_log_path - If set and individual source has local_log=true set, will create a local log in a new directory named after the source as an additional destination (useful for debugging). In a container environment, the path will always be under /tmp.
