#!/usr/bin/env python3

"""
Utility for extracting syslog-ng stats from logs and creating corresponding hosts and/or items in Zabbix so they can be monited
"""

import re
import argparse
from pyzabbix import ZabbixAPI
import os
import logging
import sys

timestamp_regex = r"^(\w\w\w\s+\d+\s\d\d:\d\d:\d\d)\s([\w\.]+)\ssyslog-ng\[\d+\]:\sLog\sstatistics;"
event_regex = r"\s(processed|dropped|queued|memory_usage)='([\w\.]+?)\(([\w\-\.]+)#?(.*?)\)=\d+'"

# Global parser for access by functions
parser = argparse.ArgumentParser(prog="metrics.py", \
    description='This utility extracts metrics from syslog-ng stats messages and optionally creates corresponding hosts and items in Zabbix')

parser.add_argument('--input_file', help='Log or file with syslog-ng stats entries', \
    default=os.environ.get('INPUT_FILE'))
parser.add_argument('--filter_file', help='File with list of metrics to be filtered out', \
    default=os.environ.get('FILTER_FILE'))
parser.add_argument('--zabbix_url', help='Zabbix URL', \
    default=os.environ.get('ZABBIX_URL'))
parser.add_argument('--zabbix_user', help='Zabbix user', \
    default=os.environ.get('ZABBIX_USER'))
parser.add_argument('--zabbix_password', help='Zabbix user password', \
    default=os.environ.get('ZABBIX_PASSWORD'))
parser.add_argument('--verify', help='Require verified SSL certificates', \
    default=os.environ.get('ZABBIX_VERIFY'), action="store_true")
parser.add_argument('--create_hosts', help='Create new host entries in Zabbix', \
    default=os.environ.get('CREATE_HOSTS'), action="store_true")
parser.add_argument('--zabbix_group', help='Group ID for newly created hosts', \
    default=os.environ.get('ZABBIX_GROUP'))
parser.add_argument('--create_items', help='Create new item entries in Zabbix', \
    default=os.environ.get('CREATE_ITEMS'), action="store_true")
parser.add_argument('--trapper_hosts', help='Network range to allow Zabbix item updates from', \
    default=os.environ.get('TRAPPER_HOSTS'))
parser.add_argument('--log_level', help='Level of logging output', \
    default=os.environ.get('LOG_LEVEL'))

# Parse cli options and environment variables
args = parser.parse_args()

if args.input_file is None:
    parser.print_help()
    exit(1)

# Log format
LOG_FORMAT = "%(message)s"

logger = logging.getLogger('Syslog-ng Stats Utility')
stream_logger = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(LOG_FORMAT)
stream_logger.setFormatter(formatter)
logger.addHandler(stream_logger)

# Check for valid log level and set loggers
try:
    if args.log_level.lower() == "debug":
        logger.setLevel(logging.DEBUG)
    elif args.log_level.lower() == "info":
        logger.setLevel(logging.INFO)
    elif args.log_level.lower() == "warn":
        logger.setLevel(logging.WARN)
    elif args.log_level.lower() == "error":
        logger.setLevel(logging.ERROR)
    elif args.log_level.lower() == "crit":
        logger.setLevel(logging.CRITICAL)
    else:
        logger.warning("Invalid or no log level specified, setting log level to INFO")
        logger.setLevel(logging.INFO)
except Exception as ex:
    logger.warning("Invalid or no log level specified, setting log level to INFO")
    logger.setLevel(logging.INFO)

# Read input
try:
    with open(args.input_file, "r") as f:
        inputs = f.read().splitlines()
except Exception as ex:
    logger.error("Unable to read input file %s : %s ", args.input_file, ex)
    exit(1)

# Read filters
filters = ""
if args.filter_file is not None:
    try:
        with open(args.filter_file, "r") as f:
            filters = f.read().splitlines()

    # Ignore missing filters
    except FileNotFoundError:
        logger.warning("Missing filter file %s", args.filter_file)
    except Exception as ex:
        logger.error("Unable to open filter file %s : %s", args.filter_file, ex)
        exit(1)

# Initialize dictionary of hosts we have metrics for
syslog_hosts = {}

# Loop through all the stats messages to be processed
for entry in inputs:

    # Check for valid log format lines starting with a timestamp
    header = re.search(r"%s" % timestamp_regex, entry)

    # Only process further if this is a valid entry
    if header:
        hostname = header.group(2)

        # Extract all metrics from a syslog-ng stats message
        metrics = re.findall(r"%s" % event_regex, entry)

        # Initialize list of keys if it doesn't exist
        if hostname in syslog_hosts:
            keys = syslog_hosts[hostname]
        else:
            keys = {}

        for metric in metrics:

            # Standardize name of metric
            key = "syslogng-stat.%s-%s" % (metric[2], metric[0])

            # Cleanup duplicate d_ or s_
            key = key.replace(".d_d_", ".d_")
            key = key.replace(".s_s_", ".s_")

            # Remove IP octet from source if present
            match = re.search(r"syslogng-stat.s_(\w+)[-_]+(\d+)[_-](\d+)-(\w+)", key)
            if match:
                key = "syslogng-stat.s_%s-%s-%s" % (match.group(1), match.group(2), match.group(4))

            # Filter out metrics we don't care about
            if filters:
                if metric[1] not in filters and metric[2] not in filters:
                    if key not in keys:
                        keys[key] = metric

            # If there are no filters defined include everything
            else:
                if key not in keys:
                    keys[key] = metric

        # Save metrics for this host for later processing
        syslog_hosts[hostname] = keys
        
# If not all the Zabbix variables are set
if not args.zabbix_url or not args.zabbix_user or not args.zabbix_password:

    # List out all the metrics discovered from the input
    logger.info("Detected and parsed the following metrics from %s:", args.input_file)
    for syslog_host in syslog_hosts:
        logger.debug("Processing host %s", syslog_host)
        for key, value in syslog_hosts[syslog_host].items():
            if logging.DEBUG >= logger.getEffectiveLevel():
                logger.debug("%s - %s %s", syslog_host, key, value)
            else:
                logger.info("%s - %s", syslog_host, key)

    # Do not check anything against Zabbix
    logger.info("Informational output only, no Zabbix credentials available")
    exit(0)

# Create ZabbixAPI class instance
try:
    zapi = ZabbixAPI(url=args.zabbix_url, user=args.zabbix_user, password=args.zabbix_password)
except Exception as ex:
    logger.error("Unable to authenticate to %s : %s", args.zabbix_url, ex)
    exit(1)

# Loop through every host we have metrics for
for syslog_host in syslog_hosts.items():

    hostname = syslog_host[0]

    try:
        host_result = zapi.do_request('host.get',
        {
            'filter': {'host': hostname}
        })
    except Exception as ex:
        logger.error("Unable to lookup host %s in Zabbix : %s", hostname, ex)
        exit(1)

    # We need exactly one host to match
    match = 1
    if len(host_result['result']) > 1:
        logger.warning("Too many matching hosts (%i) in Zabbix for %s", len(host_result['result']), hostname)
        match = 0

    # Check the number of results
    elif len(host_result['result']) == 0:
        logger.debug("No matching hosts in Zabbix for %s", hostname)
        match = 0

        # Create new host if configured to do so
        if args.create_hosts:

            if not args.zabbix_group:
                logger.warning("The zabbix_group parameter must be set with the numeric groupid to create new hosts")
                match = 0
                continue

            logger.info("Creating new Zabbix host for %s", hostname)
            try:
                # Create new Zabbix host
                result = zapi.do_request('host.create',
                {
                    'host': hostname,
                    'description': "syslog-ng stats tracked host",
                    'groups': { 'groupid': args.zabbix_group }
                })

                # Lookup Zabbix host information
                host_result = zapi.do_request('host.get',
                {
                    'filter': {'host': hostname}
                })

                match = 1

            except Exception as ex:
                logger.error("Failed to create new Zabbix host for %s : %s", hostname, ex)
                match = 0

        else:
            logger.info("Syslog-ng host %s is missing in Zabbix", hostname)
            match = 0

    # We have a matching host
    if match == 1:

        # Zabbix hostid of matching host
        try:
            hostid = int(host_result['result'][0]['hostid'])
        except Exception as ex:
            logger.error("Failed to retrive hostid for %s : %s", hostname, ex)
            continue

        # Initialize items for host
        zabbix_items = {}

        # Get all items for this host
        #results = zapi.item.get(hostids=hostid)
        try:
            results = zapi.do_request('item.get',
            {
                'hostids': hostid,
                'search': {'key_': 'syslogng-stat'}
            })
        except Exception as ex:
            logger.error("Unable to retrieve items for %s (%i) : %s", hostname, hostid, ex)
            continue

        # Assign item name and key to Zabbix host
        for item in results['result']:
            zabbix_items[item['key_']] = item['name']

        # Track if new items must be created for this host
        new_items = False

        # Loop through syslog-ng stats for syslog_host
        for key, value in syslog_host[1].items():

            #for key, value in keys:
            if key not in zabbix_items:

                # Create item for host
                if args.create_items:

                    if not args.trapper_hosts:
                        logger.warning("trapper_hosts must be set with address/range for hosts allowed to update metrics for this host")
                        logger.info("%s is missing item %s", hostname, key)
                        new_items = True

                    else:
                        new_items = True
                        logger.debug("Adding item %s for host %s (%s)", key, hostname, value)
                        try:
                            result = zapi.do_request('item.create',
                            {
                                'name': key,
                                'key_': key,
                                'hostid': hostid,
                                'type': '2',
                                'value_type': '3',
                                'allow_traps': '1',
                                'trapper_hosts': args.trapper_hosts
                            })
                        except Exception as ex:
                            logger.error("Unable to add item %s to host %s : %s", key, hostname, ex)

                # Report on missing item
                else:
                    if logging.DEBUG >= logger.getEffectiveLevel():
                        logger.debug("%s is missing item %s (%s)", hostname, key, value)
                    else:
                        logger.info("%s is missing item %s", hostname, key)
                    new_items = True

        if not new_items:
            logger.debug("%s (%i) is already fully setup for monitoring in Zabbix", hostname, hostid)
