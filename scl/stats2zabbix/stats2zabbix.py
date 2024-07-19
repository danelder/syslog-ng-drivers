"""
Copyright (c) 2024 Novacoast

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)
Syslog-ng Python destination for converting syslog-ng stats messages to Zabbix metrics through Zabbix API (https://www.zabbix.com/documentation/current/en/manual/api)

Additional documentation available at:
https://support.oneidentity.com/technical-documents/syslog-ng-premium-edition/7.0.29/administration-guide/53#TOPIC-1740255
"""

import logging
import re
import time
import datetime
import base64
from pyzabbix import ZabbixAPI, ZabbixMetric, ZabbixSender

import syslogng


class Zabbix(object):
    """
    The Zabbix destination class for sending syslog-ng stat metrics to Zabbix
    """

    def open(self):
        """Open a connection to the target service

        Should return False if opening fails"""

        try:
            self.zapi = ZabbixAPI(url=self.url, user=self.username, password=self.password)
            return True
        except Exception as ex:
            self.logger.error("Unable to open connection to %s : %s", self.url, ex)
            return False

    def close(self):
        """Close the connection to the target service"""

        try:
            self.zapi.user.logout()
            return True
        except Exception as ex:
            self.logger.error("Unable to logout from %s : %s", self.url, ex)
            return False


    def is_opened(self):
        """Check if the connection to the target is able to receive messages"""

        try:
            self.zapi.do_request('apiinfo.version')
            return True
        except Exception as ex:
            self.logger.warning("Unable to communicate with Zabbix API %s : %s", self.url, ex)
            return False

    def init(self, options):
        """This method is called at initialization time

        Should return false if initialization fails"""

        # Initialize logger for driver
        self.logger = logging.getLogger('Stats2Zabbix')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "Stats2Zabbix",
            "%(levelname)s",
            "%(message)s"
        ))

        # Configure logging for standard log format
        formatter = logging.Formatter(log_format)
        stream_logger.setFormatter(formatter)
        self.logger.addHandler(stream_logger)

        # Check for valid log level and set loggers
        if "log_level" in options:
            if options["log_level"].upper() == "DEBUG":
                self.logger.setLevel(logging.DEBUG)
            elif options["log_level"].upper() == "INFO":
                self.logger.setLevel(logging.INFO)
            elif options["log_level"].upper() == "WARN":
                self.logger.setLevel(logging.WARNING)
            elif options["log_level"].upper() == "ERROR":
                self.logger.setLevel(logging.ERROR)
            elif options["log_level"].upper() == "CRIT":
                self.logger.setLevel(logging.CRITICAL)
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.warning("Invalid or no log level specified, setting log level to INFO")

        self.logger.debug("Starting Stats2Zabbix destination driver")

        # Ensure URL parameter is defined
        if "url" in options:
            self.url = options["url"]
        else:
            self.logger.critical("No Zabbix URL configured")
            return False

        # Ensure username parameter is defined
        if "username" in options:
            self.username = options["username"]
        else:
            self.logger.critical("No username configured")
            return False

        # Ensure password parameter is defined
        if "password" in options:

            # base64 decode password
            try:
                self.password  = base64.b64decode(options["password"]).decode("utf-8")
            except Exception as e_all:
                print("Unable to decode password %s : %s", self.password, e_all)
                return False
        else:
            self.logger.critical("No password configured")
            return False

        # Setup filter_file option
        self.filters = []
        if "filter_file" in options:
            try:
                with open(options["filter_file"], "r") as f:
                    self.filters = f.read().splitlines()
            # Ignore missing filters
            except FileNotFoundError:
                self.logger.warning("Missing filter file %s", options["filter_file"])
            except Exception as ex:
                self.logger.error("Unable to open filter file %s : %s", options["filter_file"], ex)
                exit(1)

        # Capture event_regex or use default
        if "event_regex" in options:
            self.event_regex = options["event_regex"]
        else:
            self.event_regex = r"\s(processed|dropped|queued|memory_usage)='([\w\.]+?)\(([\w\-\.]+)#?(.*?)\)=(\d+)'"

        # Option to create hosts that are missing from Zabbix
        self.create_hosts = False
        if "create_hosts" in options:
            if options["create_hosts"].lower() == "true":
                self.create_hosts = True
                self.logger.info("Will create missing hosts in Zabbix automatically")

        # Option to create items that are missing from Zabbix
        self.create_items = False
        if "create_items" in options:
            if options["create_items"].lower() == "true":
                self.create_items = True
                self.logger.info("Will create missing items in Zabbix automatically")

        # Network range to allow updates for
        if "trapper_hosts" in options:
            self.trapper_hosts = options["trapper_hosts"]
        else:
            if self.create_items:
                self.logger.warning("trapper_hosts must be specified in order to create new items in Zabbix")
                self.create_items = False

        # Default Zabbix zabbix_group for newly created hosts
        if "zabbix_group" in options:

            # Extract decimal value from zabbix_group setting
            try:
                self.zabbix_group = int(re.search(r'.*?(\d+).*', options["zabbix_group"]).group(1))
            except Exception as ex:
                self.logger.error("Invalid value (%s) for zabbix_group : %s", options["zabbix_group"], ex)

                if self.create_hosts:
                    self.logger.warning("Can't create new Zabbix hosts without a valid zabbix_group value")
                    self.create_hosts = False

            self.logger.debug("Newly created Zabbix hosts will use groupid %i", self.zabbix_group)

        return True

    def deinit(self):
        """This method is called at deinitialization time"""
        pass

    def send(self, syslog_msg):
        """Send a message to the target service

        It should return True to indicate success. False will suspend the
        destination for a period specified by the time-reopen() option.
        This will be repeated for the same message retries() times.

        Alternatively, it can return the following integer values:
        self.SUCCESS: message sending was successful (same as boolean True)
        self.ERROR: message sending was unsuccessful (same as boolean False)
        self.DROP: the message cannot be sent, it should be dropped immediately
        self.QUEUED: the message is not sent immediately, it will be sent in a batch with the flush method
        self.NOT_CONNECTED: the message is put back into the queue, the open method will be called until it succeeds
        self.RETRY: the message is put back into the queue, to retry send it retries() times, then fallback to self.NOT_CONNECTED
        """

        # Extract msg from syslog_msg
        try:
            msg = syslog_msg['MESSAGE'].decode('utf-8')
            hostname = syslog_msg['HOST'].decode('utf-8')
            timestamp = syslog_msg['ISODATE'].decode('utf-8')
        except Exception as ex:
            self.logger.warning("Invalid syslog message (%s) : %s", syslog_msg, ex)
            return self.DROP

        # Extract all metrics from a syslog-ng stats message
        result = re.findall(self.event_regex, msg)

        if len(result) > 1:

            # Convert message timestamp to datetime object if possible
            try:
                datestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S%z")
            except Exception as ex:
                self.logger.warning("Invalid timestamp format (%s) : %s", timestamp, ex)
                datestamp = datetime.datetime.utcnow()

            # Convert timestamp to Unix epoch time
            unix = int(datestamp.strftime('%s'))

            self.logger.debug("Processing statistics for %s at %s", hostname, datestamp)

            # Initialize dict of metrics
            metrics = {}

            # Initialize list of metrics to send to Zabbix
            ZabbixMetrics = []

            # Whether we created new items or not
            newitems = False

            # Process each metric as needed
            for metric in result:

                # Extract key and value
                try:
                    # Standardize name of metric
                    key = "syslogng-stat.%s-%s" % (metric[2], metric[0])
                    # Make sure value is an integer
                    value = int(metric[4])

                    # Cleanup duplicate d_ or s_
                    key = key.replace(".d_d_", ".d_")
                    key = key.replace(".s_s_", ".s_")

                    # Remove IP octet from source if present
                    match = re.search(r"syslogng-stat.s_(\w+)[-_]+(\d+)[_-](\d+)-(\w+)", key)
                    if match:
                        key = "syslogng-stat.s_%s-%s-%s" % (match.group(1), match.group(2), match.group(4))

                    # Filter out result we don't care about
                    if self.filters:
                        if metric[1] not in self.filters and metric[2] not in self.filters:

                            self.logger.debug("Detected filtered stat %s from %s", key, metric)

                            # Add values if we're consolidating metrics
                            if key in metrics:
                                metrics[key] = metrics[key] + value
                            else:
                                metrics[key] = value

                    # If there are no filters defined include everything
                    else:
                        self.logger.debug("Detected unfiltered stat %s from %s", key, metric)
                        # Add values if we're consolidating metrics
                        if key in metrics:
                            metrics[key] = metrics[key] + value
                        else:
                            metrics[key] = value

                except Exception:
                    self.logger.info("Invalid metric %s", metric)

            try:
                # Check for matching Zabbix host
                host_result = self.zapi.do_request('host.get',
                {
                    'filter': {'host': hostname}
                })
            except Exception as ex:
                self.logger.warning("Unable to lookup Zabbix hosts : %s", ex)
                return self.ERROR

            # We need exactly one host to match
            match = 1
            if len(host_result['result']) > 1:
                self.logger.warning("Too many matching hosts (%i) in Zabbix for %s", len(host_result['result']), hostname)
                match = 0

            # If no hosts match
            elif len(host_result['result']) == 0:
                self.logger.debug("No matching hosts in Zabbix for %s", hostname)
                match = 0

                # Create new host if configured to do so
                if self.create_hosts:

                    self.logger.info("Creating new Zabbix host for %s", hostname)
                    try:
                        # Create new Zabbix host
                        result = self.zapi.do_request('host.create',
                        {
                            'host': hostname,
                            'description': "syslog-ng stats tracked host",
                            'groups': { 'groupid': self.zabbix_group }
                        })

                        # Give Zabbix server a chance to process new host
                        time.sleep(10)

                        # Lookup Zabbix host information
                        host_result = self.zapi.do_request('host.get',
                        {
                            'filter': {'host': hostname}
                        })

                        match = 1

                    except Exception as ex:
                        self.logger.error("Failed to create new Zabbix host for %s : %s", hostname, ex)
                        return self.ERROR

                else:
                    self.logger.warning("Syslog-ng host %s is missing in Zabbix, ignoring stats", hostname)
                    return self.DROP

            # We have a matching host
            if match == 1:

                try:
                    # Zabbix hostid of matching host
                    hostid = host_result['result'][0]['hostid']
                except Exception as ex:
                    self.logger.error("Invalid host results returned from Zabbix : %s", ex)
                    return self.ERROR

                # Initialize items for host
                zabbix_items = {}

                try:
                    # Get all items for this host
                    results = self.zapi.do_request('item.get',
                    {
                        'hostids': hostid,
                        'search': {'key_': 'syslogng-stat'}
                    })
                except Exception as ex:
                    self.logger.error("Unable to lookup items for hostid %i : %s", hostid, ex)

                # Assign item name and key to Zabbix host
                for item in results['result']:
                    zabbix_items[item['key_']] = item['name']

                # Loop through syslog-ng stats for syslog_host
                for key, value in metrics.items():

                    # If this metric isn't already in Zabbix
                    if key not in zabbix_items:

                        # Create item for host
                        if self.create_items:
                            self.logger.debug("Adding item %s for host %s", key, hostname)
                            try:
                                result = self.zapi.do_request('item.create',
                                {
                                    'name': key,
                                    'key_': key,
                                    'hostid': hostid,
                                    'type': '2',
                                    'value_type': '3',
                                    'allow_traps': '0',
                                    'trapper_hosts': self.trapper_hosts
                                })

                                newitems = True
                                ZabbixMetrics.append(ZabbixMetric(hostname, key, int(value), unix))

                            except Exception as ex:
                                self.logger.error("Unable to create item %s for host %s : %s", key, hostname, ex)
                                return self.ERROR

                        # Report on missing item
                        else:
                            self.logger.warning("%s is missing item %s (skipping stat)", hostname, key)

                    else:
                        ZabbixMetrics.append(ZabbixMetric(hostname, key, int(value), unix))

            # Give Zabbix server time to process new items
            if newitems:
                self.logger.debug("Waiting 15 seconds for processing of new Zabbix items")
                time.sleep(15)

            # Send events to Zabbix
            try:
                destination = re.search(r'\/\/([a-zA-Z0-9\.]+)', self.url).group(1)
                zbx = ZabbixSender(destination)
                zbx.send(ZabbixMetrics)
                return self.SUCCESS
            except Exception as ex:
                self.logger.error("Unable to send Zabbix metrics : %s", ex)
                return self.ERROR

        # msg doesn't appear to be a valid stats message
        else:
            self.logger.debug("Invalid stats message (%s) using %s : %s", msg, self.event_regex, syslog_msg)
            return self.DROP
