# stats2zabbix

## Purpose

Syslog-ng can generate statistics messages which include detailed metrics on log flows. Getting those metrics into Zabbix for monitoring and performance analysis is sublime.

## Dependencies

Both the Python utility script and syslog-ng driver require [py-zabbix](https://pypi.org/project/py-zabbix/) for Zabbix integration. This can be installed at the system level using pip and for syslog-ng PE, can be installed with:


	/opt/syslog-ng/bin/python3 -m pip install py-zabbix

Or use the base OS Python modules for syslog-ng by modifying plugin.conf for the correct local path if available:

    sys.path.append("/usr/lib/python3.8/site-packages/")

## Components

### metrics.py

The metrics.py script can parse a text file containing syslog-ng statistics and produce a list of hostnames and metrics or optionally create new hosts and/or items in Zabbix to match them. Arguments can be passed as environment variables or via cli options:

    usage: metrics.py [-h] [--input_file INPUT_FILE] [--filter_file FILTER_FILE] [--zabbix_url ZABBIX_URL] [--zabbix_user ZABBIX_USER] [--zabbix_password ZABBIX_PASSWORD] [--verify] [--create_hosts] [--zabbix_group ZABBIX_GROUP]
                  [--create_items] [--trapper_hosts TRAPPER_HOSTS] [--log_level LOG_LEVEL]

    This utility extracts metrics from syslog-ng stats messages and optionally creates corresponding hosts and items in Zabbix

    options:
    -h, --help            show this help message and exit
    --input_file INPUT_FILE
                            Log or file with syslog-ng stats entries
    --filter_file FILTER_FILE
                            File with list of metrics to be filtered out
    --zabbix_url ZABBIX_URL
                            Zabbix URL
    --zabbix_user ZABBIX_USER
                            Zabbix user
    --zabbix_password ZABBIX_PASSWORD
                            Zabbix user password
    --verify              Require verified SSL certificates
    --create_hosts        Create new host entries in Zabbix
    --zabbix_group ZABBIX_GROUP
                            Group ID for newly created hosts
    --create_items        Create new item entries in Zabbix
    --trapper_hosts TRAPPER_HOSTS
                            Network range to allow Zabbix item updates from
    --log_level LOG_LEVEL
                            Level of logging output

The only required parameter is --input_file (INPUT_FILE) which is the path to the file containing the syslog-ng statistics message(s). Specifying Zabbix parameters will allow the script to check against the Zabbix environment to see if the host and items already exist so that it will only list/create missing ones. An example session which will create new hosts and items would look like:

    ZABBIX_PASSWORD=secret ./metrics.py --input_file /var/log/stats.log --filter_file /opt/syslog-ng/etc/stats-filters.txt --zabbix_url "https://zabbix" --zabix_user Admin --create_hosts  --create_items --trapper_hosts "10.10.20.0/24"

All parameters can also be passed as environment variables though:

    INPUT_FILE=/var/log/stats.log FILTER_FILE=/opt/syslog-ng/etc/stats-filters.txt ZABBIX_URL="https://zabbix" ZABBIX_USER=Admin ZABBIX_PASSWORD=secret TRAPPER_HOSTS="10.10.20.0/24" ./metrics.py --create_hosts  --create_items

The FILTER_FILE is a text file containing a list of syslog-ng statistics which shouldn't be collected. In the default filters.txt file the following are filtered:

    di_config_change
    di_internal_alert
    di_messages
    di_class_violation
    di_ssb
    ds_local
    ds_center
    dst.file
    dst.program
    dst.logstore
    dst.file
    center
    src.program
    src.facility
    src.host
    src.internal
    src.journald
    src.severity
    src.sender
    si.local
    si.internal
    internal_source
    internal_queue_length
    localhost
    msg_clones
    payload_reallocs
    scratch_buffers_count
    scratch_buffers_bytes
    sdata_updates
    tag

## stats2zabbix.py

This is a syslog-ng Python destination which takes syslog-ng statistics as a source, converts them into Zabbix metrics, and sends them to Zabbix. It can optionally create Zabbix hosts and items as needed as well. To use this driver, the following steps are recommended:

1. Create a new SCL directory named hypr (e.g., /opt/syslog-ng/share/syslog-ng/include/scl/stats2zabbix/)
2. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/stats2zabbix/plugin.conf
3. Save symantec.py to /opt/syslog-ng/share/syslog-ng/include/scl/stats2zabbix/syslogng-stats.py
4. Create a new syslog-ng destination with the required parameters

Certain parameters are required for the driver to function:

    destination d_zabbix {
        python(
            class("stats2zabbix.Zabbix")
            options(
                "url","<Zabbix URL>"
                "username","<Zabbix username>"
                "password","<Base64 encoded Zabbix password>"
            )
        );
    };

A more fully configured driver includes additional options:

    destination d_zabbix {
        python(
            class("stats2zabbix.Zabbix")
            options(
                "url","<Zabbix URL>"
                "username","<Zabbix username>"
                "password","<Base64 encoded Zabbix password>"
                "filter_file","<path to event filters>"
                "event_regex","<custom regex for filtering events>" # defaults to \\s(processed|dropped|queued|memory_usage)='([\\w\\.]+?)\\((\\w+)#?(.*?)\\)=(\\d+)'
                "log_level","<DEBUG|INFO|WARN|ERROR>" # optional - defaults to INFO
                "create_hosts","<true|false>" # whether to create new Zabbix hosts for any hosts we collect syslog-ng statistics from
                "create_items","<true|false>" # whether to create new Zabbix items for any hosts we collect syslog-ng statistics from
                "trapper_hosts","<IP or network range>" # for newly created Zabbix items, which network(s) to allow updates from
                "zabbix_group","<Integer Zabbix group ID>" # for newly created Zabbix hosts, which group they should be in
            )
        );
    };

As an example:

    destination d_zabbix {
        python(
            class("stats2zabbix.Zabbix")
            options(
                "url","https://zabbix"
                "username","Admin"
                "password","EmFIYml2"
                "filter_file","/opt/syslog-ng/etc/conf.d/filter.txt"
                "event_regex","\\s(processed|dropped|queued|memory_usage)='([\\w\\.]+?)\\((\\w+)#?(.*?)\\)=(\\d+)'"
                "log_level","debug"
                "create_hosts","true"
                "create_items","true"
                "trapper_hosts","172.21.143.0/24"
                "zabbix_group","20"
            )
        );
    };

### Driver options

**url** - The URL to the Zabbix server for REST API and Zabbix sender access

**username** - The Zabbix user authorized for the REST API to make modifications and perform lookups

**password** - The base64 encoded password for the Zabbix user

filter_file - The path to the filter file containing metrics types to be filtered

event_regex - The custom regex (if needed) for capturing metrics from a statistics message

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng (optional, defaults to INFO)

create_hosts - Whether to create new hosts in Zabbix for any host syslog-ng statistics are available for

create_items - Whether to create new items in Zabbix for any metrics that are available

trapper_hosts - What address or network range to allow updates from (only used for creating new items)

zabbix_group - The numeric Group ID for the group new Zabbix hosts should be assigned to