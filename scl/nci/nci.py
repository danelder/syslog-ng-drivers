"""
Copyright (c) 2024 Pillr

Use of this source code is governed by an MIT-style license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)
Syslog-ng Python parser for converting syslog-ng stats messages to key value pairs or alerts for upstream consumption

Additional documentation available at:
https://support.oneidentity.com/technical-documents/syslog-ng-premium-edition/7.0.33/administration-guide/90#TOPIC-2036755
"""

import logging
import re
import os
import configparser
import datetime
import smtplib
import ssl
import pickle
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dateutil import parser
import syslogng

class DedupAlerts(object):
    """
    syslog-ng parser for deduped alerting
    """

    def open(self):
        """
        Validate email connection parameters for sending alerts
        """

        message = MIMEMultipart()

        message["From"] = self.sender
        message["To"] = self.test_recipient
        message["Subject"] = "Syslog-ng Dedup Alert Engine Initializing"
        message.attach( MIMEText("Please disregard this message"))

        # Send test email to validate SMTP settings
        if not self.email_alert(self.test_recipient, message):
            self.logger.error("Unable to send email")
            return False

        return True


    def init(self, options):
        """
        This method is called at initialization time
        Should return false if initialization fails
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('DedupAlerts')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = 'DedupAlerts - %(levelname)s - %(message)s'

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

        # Global watchlist and events
        self.watchlist = []
        self.events = {}

        # Global counters
        self.processed = 0
        self.dropped = 0
        self.total = 0

        # Global variables
        self.ignore = "N/A"

        # Get/set all mail related options
        self.sender = "root@localhost"
        if "mail_sender" in options:
            self.sender = options["mail_sender"]

        self.password = False
        if "mail_password" in options:
            self.password = options["mail_password"]

        self.encryption = False
        if "mail_encryption" in options:
            self.encryption = options["mail_encryption"]

        self.smtp_server = "localhost"
        if "mail_server" in options:
            self.smtp_server = options["mail_server"]

        self.port = 25
        if "mail_port" in options:
            try:
                self.port = int(options["mail_port"])
            except Exception:
                self.logger.error("Invalid SMTP port specified : %s", options["mail_port"])

        self.trust_certificate = True
        if "mail_trust" in options:
            if options["mail_trust"].lower() == "false":
                self.trust_certificate = False

        self.test_recipient = "root@localhost"
        if "mail_test_recipient" in options:
            self.test_recipient = options["mail_test_recipient"]

        self.sender = "root@localhost"
        if "mail_sender" in options:
            self.sender = options["mail_sender"]

        # Check for state database options
        if "state_db" in options:
            self.state_db = options["state_db"]
            # Set stale_hours from options or default to 12
            if "stale_hours" in options:
                self.stale_hours = 12
                try:
                    self.stale_hours = int(options["stale_hours"])
                except Exception:
                    self.logger.error("Invalid value for stale_hours: %s", options["stale_hours"])

            # Load previous state from last shutdown
            if not self.load_events():
                self.logger.error("Error accessing %s for tracking state between restarts", self.state_db)

        # Ensure alert configuration file is defined
        if not options["alerts_ini"]:
            self.logger.error("No alerts_ini configuration value set")
            return False

        # Read in alerts definitions
        self.alerts_ini = options["alerts_ini"]
        parser = configparser.ConfigParser()
        parser.read(self.alerts_ini)

        try:
            configurations = parser.sections()
            for configuration in configurations:

                alert = {}
                try:
                    # Get configuration values from ini
                    pattern = parser.get(configuration, "pattern")
                    filter_pattern = parser.get(configuration, "filter_pattern", fallback=False)
                    recipient = parser.get(configuration, "recipient")
                    template = parser.get(configuration, "template")
                    keys = parser.get(configuration, "keys")
                    use_dns = parser.get(configuration, "use_dns", fallback=False)
                    user = parser.get(configuration, 'user', fallback=False)
                    computer = parser.get(configuration, "computer", fallback=False)
                    log_sources = parser.get(configuration, "log_sources", fallback=False)
                    high_threshold = parser.getint(configuration, "high_threshold", fallback=1)
                    time_span = parser.getint(configuration, "time_span", fallback=60)
                    reset_time = parser.getint(configuration, "reset_time", fallback=60)
                    timestamp = parser.get(configuration, "timestamp", fallback=False)
                    timestamp_format = parser.get(configuration, "timestamp_format", fallback=False)
                    mandatory_fields = parser.get(configuration, "mandatory_fields", fallback=False)
                    custom_field = parser.get(configuration, "custom_field", fallback=False)

                    # Handle required parameters
                    if not pattern:
                        self.logger.critical("pattern is a required parameter for %s", configuration)
                    if not recipient:
                        self.logger.critical("recipient is a required parameter for %s", configuration)
                    if not template:
                        self.logger.critical("template is a required parameter for %s", configuration)

                    # Don't let slow/broken DNS break the driver
                    if use_dns:
                        socket.setdefaulttimeout(10)

                    # Convert the pattern regex to a logical AND search expression if whitespace is present
                    if re.search(" ", pattern):
                        # Split pattern by whitespace
                        logical_pattern = ""
                        for substring in pattern.split(" "):
                            # Use lookaheads for matching each substring
                            logical_pattern = logical_pattern + "(?=.*" + substring + ")"
                        # Match remainder of log
                        pattern = logical_pattern + ".*"
                        self.logger.debug("Converted search expression %s to %s", parser.get(configuration, "pattern"), pattern)

                    # Store configuration parameters for this alert
                    alert['name'] = configuration
                    alert['recipient'] = recipient
                    alert['pattern'] = pattern
                    alert['filter_pattern'] = filter_pattern
                    alert['keys'] = keys
                    alert['use_dns'] = use_dns
                    alert['template'] = template
                    alert['high_threshold'] = high_threshold
                    alert['time_span'] = time_span
                    alert['reset_time'] = reset_time
                    alert['timestamp'] = timestamp
                    alert['timestamp_format'] = timestamp_format
                    alert['mandatory_fields'] = mandatory_fields

                    # Compile regex for performance
                    pattern_regex = re.compile(pattern)
                    alert['pattern_regex'] = pattern_regex
                    if filter_pattern:
                        filter_pattern_regex = re.compile(filter_pattern)
                        alert['filter_pattern_regex'] = filter_pattern_regex
                    if user:
                        user_regex = re.compile(user)
                        alert['user_regex'] = user_regex
                    if computer:
                        computer_regex = re.compile(computer)
                        alert['computer_regex'] = computer_regex
                    if log_sources:
                        log_sources_regex = re.compile(log_sources)
                        alert['log_sources_regex'] = log_sources_regex
                    if timestamp:
                        timestamp_regex = re.compile(timestamp)
                        alert['timestamp_regex'] = timestamp_regex
                    if custom_field:
                        custom_field_regex = re.compile(custom_field)
                        alert['custom_field_regex'] = custom_field_regex

                    # Add this alert to the global watchlist
                    self.logger.debug("Adding %s (%s) to monitored alerts", configuration, pattern)
                    self.watchlist.append(alert)
                except Exception as ex:
                    self.logger.warning("Missing or invalid options for %s configuration : %s", configuration, ex)
                    return False

        except Exception as ex:
            self.logger.error("Error parsing %s : %s", self.alerts_ini, ex)
            return False

        return True

    def deinit(self):
        """
        Flush log file to disk
        """

        self.logger.debug("%i alarms generated (%i events did not generate alarms) out of %i logs", self.processed, self.dropped, self.total)

        #self.logger.debug(f"{self.events}")

        # If configured to maintain state between restarts
        if self.state_db:
            timestamp_count = 0
            events_count = 0
            alarm_count = 0
            # Count events and timestamps in events
            for category in self.events:
                for event in self.events[category]:
                    events_count = events_count + 1
                    timestamp_count = timestamp_count + len(self.events[category][event]['timestamps'])
                    alarm_count = alarm_count + len(self.events[category][event]['alarms'])
            # Dump events to state file using pickle
            try:
                f = open(self.state_db, 'wb')
                pickle.dump(self.events, f)
                f.flush()
                f.close()
                self.logger.info("Flushed %i events with %i timestamps with %i alarms to %s",\
                                 events_count, timestamp_count, alarm_count, self.state_db)
            except Exception as ex:
                self.logger.error("Unable to flush events to %s : %s", self.state_db, ex)
        else:
            self.logger.info("No configuration for %s, event state discarded", self.state_db)


    def tzconvert(self, timestamp):
        """
        Convert timezone string values to UTC offsets for reliable parsing
        """

        try:
            timestamp = re.sub(r'EST-DST', '-0400', timestamp)
            timestamp = re.sub(r'EST', '-0500', timestamp)
            timestamp = re.sub(r'EDT', '-0400', timestamp)
            timestamp = re.sub(r'CST-DST', '-0500', timestamp)
            timestamp = re.sub(r'CST', '-0600', timestamp)
            timestamp = re.sub(r'CDT', '-0500', timestamp)
            timestamp = re.sub(r'MST', '-0700', timestamp)
            timestamp = re.sub(r'MDT', '-0600', timestamp)
            timestamp = re.sub(r'PST', '-0800', timestamp)
            timestamp = re.sub(r'PDT', '-0700', timestamp)
            timestamp = re.sub(r'UTC', '-0000', timestamp)
        except Exception as ex:
            self.logger.warning("Error substituting timezone in %s : %s", timestamp, ex)
        return timestamp

    def send(self,log_message):
        """
        Parse out syslog-ng stats messages to extract metrics and generate alerts if needed
        """
        self.total = self.total + 1
        # Set values from log_message
        syslog_timestamp = log_message['S_ISODATE']
        message = log_message['MESSAGE']

        # Message hasn't been filtered out
        filtered = False

        # Convert bytes to strings if needed
        if isinstance(syslog_timestamp, bytes):
            syslog_timestamp = syslog_timestamp.decode("utf-8")
        if isinstance(message, bytes):
            message = message.decode("utf-8")

        # Check every alert in the watchlist against this log
        for alert in self.watchlist:

            # Check for matching pattern in message
            if alert['pattern_regex'].search(message):

                # Check for filtered pattern matching in message
                if "filter_pattern_regex" in alert and alert['filter_pattern_regex'].search(message):
                    # Ignore this log message
                    filtered = True
                    break

                # Create new metadata object
                metadata = {}

                # Extract and set user from event if available
                if "user_regex" in alert:
                    try:
                        # Loop through groups to support OR regex searches
                        for group in alert['user_regex'].search(message).groups():
                            if group is not None:
                                metadata['user'] = group
                    except:
                        metadata['user'] = self.ignore

                # Extract and set computer from event if available
                if "computer_regex" in alert:
                    try:
                        # Loop through groups to support OR regex searches
                        for group in alert['computer_regex'].search(message).groups():
                            metadata['computer'] = group
                    except:
                        metadata['computer'] = self.ignore

                # Extract and set log_sources from event if available
                if "log_sources_regex" in alert:
                    try:
                        # Loop through groups to support OR regex searches
                        for group in alert['log_sources'].search(message).groups():
                            metadata['log_sources'] = group
                    except:
                        metadata['log_sources'] = self.ignore

                # Extract and set log_sources from event if available
                if "custom_field_regex" in alert:
                    try:
                        # Loop through groups to support OR regex searches
                        for group in alert['custom_field'].search(message).groups():
                            metadata['custom_field'] = group
                    except:
                        metadata['custom_field'] = self.ignore
                
                # Ensure we have all mandatory fields as part of our message
                if "mandatory_fields" in alert and alert['mandatory_fields']:
                    for mandatory_field in alert['mandatory_fields'].split(','):
                        try:
                            # There was no match when searcing for this field in the message
                            if metadata[mandatory_field] == self.ignore:
                                self.logger.debug("Ignoring log message that doesn't include %s : %s", mandatory_field, message)
                                return self.SUCCESS
                        except Exception as ex:
                            self.logger.debug("Mandatory field %s is not supported for this event type (%s)", mandatory_field, alert['name'])
                            return self.SUCCESS

                # Set metadata for syslog-ng available macros
                metadata['LOGHOST'] = log_message['LOGHOST']
                metadata['SOURCEIP'] = log_message['SOURCEIP']
                metadata['FULLHOST'] = log_message['FULLHOST']
                metadata['FULLHOST_FROM'] = log_message['FULLHOST_FROM']

                # Cleanup metadata fields
                if isinstance(metadata['LOGHOST'], bytes):
                    metadata['LOGHOST'] = metadata['LOGHOST'].decode("utf-8")
                if isinstance(metadata['SOURCEIP'], bytes):
                    metadata['SOURCEIP'] = metadata['SOURCEIP'].decode("utf-8")
                if isinstance(metadata['FULLHOST'], bytes):
                    metadata['FULLHOST'] = metadata['FULLHOST'].decode("utf-8")
                if isinstance(metadata['FULLHOST_FROM'], bytes):
                    metadata['FULLHOST_FROM'] = metadata['FULLHOST_FROM'].decode("utf-8")

                # Use received time as default timestamp
                metadata['alert_date'] = datetime.datetime.strptime(syslog_timestamp, "%Y-%m-%dT%H:%M:%S%z")

                # Extract timestamp from event if available and convert to datetime
                raw_timestamp = ""
                if "timestamp_regex" in alert:
                    try:
                        # Extract timestamp from message if possible
                        match = alert['timestamp_regex'].search(message)
                        if match is not None:
                            # Loop through all match groups for OR timestamp regex matching
                            for raw_timestamp in match.groups():
                                if raw_timestamp:

                                    # If the format of the timestamp has already been defined
                                    if alert['timestamp_format']:
                                        # Convert the timestamp using the defined timestamp format
                                        metadata['alert_date'] = datetime.datetime.strptime(raw_timestamp, alert['timestamp_format'])
                                    else:
                                        # Convert string timezone to UTC hourly offset if possible
                                        raw_timestamp = self.tzconvert(raw_timestamp)
                                        # Convert to datetime format using dateutil
                                        metadata['alert_date'] = parser.parse(raw_timestamp)

                                    # Valid timestamp found, no need to search for more
                                    break
                        else:
                            self.logger.debug("No matching timestamps found %s", message)

                    except Exception as ex:
                        self.logger.debug("Invalid timestamp (%s) in %s : %s", raw_timestamp, message, ex)
                        metadata['alert_date'] = datetime.datetime.strptime(syslog_timestamp, "%Y-%m-%dT%H:%M:%S%z")

                # Convert to unix timestamp from datetime
                timestamp = int(metadata['alert_date'].timestamp())

                # Start with assumption that event doesn't trigger an alert
                alertable = False

                # If we should alert on every event
                alert_always = False
                if alert['keys'] == "" or alert['reset_time'] == 0:
                    alert_always = True

                # If we need to compare alert against timeline of alerts
                else:
                    # Build unique key for deduping alerts from keys fields
                    key = ""
                    for value in alert['keys'].split(','):
                        # Ensure metadata[value] exists or deinit it if it doesn't
                        if value not in metadata:
                            error = f"{value} is not a valid field from {alert['name']} for use as a unique key in {self.alerts_ini} for {message}"
                            message = MIMEMultipart()
                            message["From"] = self.sender
                            message["To"] = self.test_recipient
                            message["Subject"] = "Key Error in Syslog-ng Dedup Alert Engine"
                            message.attach( MIMEText(error))
                            self.email_alert(self.test_recipient, message)
                            self.logger.error(error)
                            self.dropped = self.dropped + 1
                            return self.SUCCESS
                        # Ensure metadata[value] isn't empty
                        if not metadata[value]:
                            self.logger.warning("Field %s not found for uniqueness key in %s", value, message)
                        else:
                            # Ensure metadata[value] is a string
                            if isinstance(metadata[value], bytes):
                                metadata[value] = metadata[value].decode("utf-8")
                            # Concatenate key value(s)
                            key = key + metadata[value] + "-"

                    # Ensure we have a usable key if required
                    if key == "":
                        error = f"Invalid field(s) specified for keys in {alert['name']}, please check the Keys configuration in {self.alerts_ini} for {message}"
                        message = MIMEMultipart()
                        message["From"] = self.sender
                        message["To"] = self.test_recipient
                        message["Subject"] = "Critical Key Error in Syslog-ng Dedup Alert Engine"
                        message.attach( MIMEText(error))
                        self.email_alert(self.test_recipient, message)
                        self.logger.critical(error)
                        self.dropped = self.dropped + 1
                        self.deinit()
                        exit(1)

                    # If this type of event has never occured
                    if alert['name'] not in self.events:
                        self.events[alert['name']] = {}

                    # If this type of event for this key has occured
                    if key in self.events[alert['name']]:
                        event = self.events[alert['name']][key]

                    # If this type of event for this key has never occured
                    else:
                        event = {}
                        event['timestamps'] = []
                        event['num_events'] = 0
                        event['alarms'] = []
                        self.events[alert['name']][key] = event

                    # Check if this event should be alertable and cleanup
                    self.events[alert['name']][key], alertable = self.insert_timestamp(alert, event, timestamp)

                # If this is an alertable event
                if alertable or alert_always:

                    # Do not bother with timeline for alert_always events
                    if alert_always:
                        message, temp_event = self.gen_alert(\
                                new_alert=alert,
                                new_event=None,
                                new_metadata=metadata,
                                new_timestamp=timestamp,
                                new_log=message)
                    else:
                        message, temp_event = self.gen_alert(\
                                new_alert=alert,
                                new_event=self.events[alert['name']][key],
                                new_metadata=metadata,
                                new_timestamp=timestamp,
                                new_log=message)

                    # Send email alert
                    if self.email_alert(alert['recipient'], message):
                        # Overwrite event with modified (alarmed) event information if required
                        if alertable:
                            self.events[alert['name']][key] = temp_event
                        self.processed = self.processed + 1
                        return self.SUCCESS
                    else:
                        # Trigger re-opening connection
                        self.logger.error("Failed to send alert email")
                        return self.NOT_CONNECTED

                # Matching alert entry found, move on to next message
                self.dropped = self.dropped + 1
                return self.SUCCESS

        # No matching alert entry found
        self.dropped = self.dropped + 1

        # If message wasn't filtered, output debug information for non-matching message
        if not filtered:
            self.logger.debug("No matching alerts for %s", message)

        return self.SUCCESS

    def insert_timestamp(self, new_alert, new_event, new_timestamp):
        """
        Inserts a new timestamp for a given alert into the series and determines if an alert condition exists
        """

        # Incriment num_event counter
        new_event['num_events'] = new_event['num_events'] + 1

        # Check if newest timestamp is within an existing alarm window
        for alarm in new_event['alarms']:
            if new_timestamp >= alarm - new_alert['time_span']:
                if new_timestamp <= alarm + new_alert['reset_time']:
                    # This event falls within an existing alarm window
                    #self.logger.debug(f"Event {new_event} within alarm {alarm} : {new_timestamp}")
                    return new_event, False

        # Events that should be alerted on for a single occurrence
        if new_alert['high_threshold'] == 1:

            # Make sure this isn't a duplicate based on timestamp
            if new_timestamp in new_event['alarms']:
                #self.logger.debug(f"Duplicate event timestamp detected for {new_event}")
                return new_event, False
            return new_event, True

        # Events that should be alerted on for multiple occurrences
        else:
            # Add timestamp to list and sort them
            new_event['timestamps'].append(new_timestamp)
            new_event['timestamps'].sort()
            timestamps = len(new_event['timestamps'])
            #self.logger.debug(f"Processing event {new_event} for alert {new_alert['name']}")

            # If there aren't enough events to trigger an alarm
            if timestamps < new_alert['high_threshold']:
                return new_event, False

            # Find this timestamp index in the list of timestamps
            position = new_event['timestamps'].index(new_timestamp)

            # Count duplicates in list not including the timestamp itself
            duplicates = new_event['timestamps'].count(new_timestamp) - 1

            # If there are at least high_threshold events after this timestamp
            if position + new_alert['high_threshold'] + duplicates <= timestamps:

                # Max timestamp value to evaluate for first entry in list
                max_timestamp_index = position + duplicates

            else:
                # Max timestamp  for first entry is at end of list
                max_timestamp_index = timestamps - new_alert['high_threshold']

            # If there are more than high_threshold events before this one
            if position - new_alert['high_threshold'] >= 0:

                # Start comparing timestamps high_threshold events before this one
                min_timestamp_index = position - new_alert['high_threshold']

            else:
                # Start comparing timestamps high_threshold events into the list
                min_timestamp_index = 0

            # Compare the delta between min_timestamp_index and min_timestamp_index + high_threshold up to max_timestamp_index
            while min_timestamp_index <= position and max_timestamp_index:
                # If the high timestamp - low timestamp is <= time_span
                low = new_event['timestamps'][min_timestamp_index]
                high = new_event['timestamps'][min_timestamp_index + new_alert['high_threshold'] - 1]
                if high - low <= new_alert['time_span']:
                    return new_event, True

                # Incriment min_timestamp_index position
                min_timestamp_index = min_timestamp_index + 1

        # No alert to generate
        return new_event, False

    def gen_alert(self, new_alert, new_event, new_metadata, new_timestamp, new_log):
        """
        Generate an alert with the required template variable subsitution
        """

        body = new_alert['template']

        # If reverse DNS lookups are enabled
        if new_alert['use_dns']:
            # Loop through the fields to be used for reverse DNS lookups
            for address_field in new_alert['use_dns'].split(','):
                # If this field is part of the message metadata
                if address_field in new_metadata:
                    try:
                        # Perform reverse DNS lookup
                        resolved, alias, addresslist = socket.gethostbyaddr(new_metadata[address_field])
                        new_metadata[address_field] = resolved
                    except Exception as ex:
                        self.logger.debug("Reverse DNS lookup of %s failed : %s", new_metadata[address_field], ex)

        message = MIMEMultipart()
        message["From"] = self.sender
        message["To"] = new_alert['recipient']

        # Replace template variables
        if new_alert.get("recipient"):
            body = body.replace('$RECIPIENT', new_alert['recipient'])
        if new_alert.get("pattern"):
            body = body.replace('$PATTERN', new_alert['pattern'])
        if new_metadata.get("log_sources"):
            body = body.replace('$LOG_SOURCES', new_metadata['log_sources'])
        if new_metadata.get("user"):
            body = body.replace('$USER', new_metadata['user'])
        if new_metadata.get("computer"):
            body = body.replace('$COMPUTER', new_metadata['computer'])
        if new_metadata.get("custom_field"):
            body = body.replace('$CUSTOM_FIELD', new_metadata['custom_field'])
        if new_metadata.get("alert_date"):
            body = body.replace('$ALERT_TIME', str(new_metadata['alert_date']))
        if new_alert.get("high_threshold"):
            body = body.replace('$HIGH_THRESHOLD', str(new_alert['high_threshold']))
        if new_alert.get("time_span"):
            body = body.replace('$TIME_SPAN', str(new_alert['time_span']))
        if new_alert.get("reset_time"):
            body = body.replace('$RESET_TIME', str(new_alert['reset_time']))
        if new_event is not None and new_event.get("num_events"):
            body = body.replace('$NUM_EVENTS', str(new_event['num_events']))
        if new_metadata.get("LOGHOST"):
            body = body.replace('$LOGHOST', str(new_metadata['LOGHOST']))
        if new_metadata.get("SOURCEIP"):
            body = body.replace('$SOURCEIP', str(new_metadata['SOURCEIP']))
        if new_metadata.get("FULLHOST"):
            body = body.replace('$FULLHOST', str(new_metadata['FULLHOST']))
        if new_metadata.get("FULLHOST_FROM"):
            body = body.replace('$FULLHOST_FROM', str(new_metadata['FULLHOST_FROM']))
        if new_log:
            body = body.replace('$LOG', new_log)

        # Extract subject if it was part of template
        match = re.search("^Subject:\s*(.+?)\n", body)
        if match:
            message["Subject"] = match.group(0)

            # Delete subject from body
            body = re.sub(r'^Subject:\s*(.+?)\n', '', body)

        # MIME convert and attach message body
        message.attach(MIMEText(body))

        # Cleanup timestamps if required
        if new_event is not None:

            # Reset event counter
            new_event['num_events'] = 0

            # Add this alarm to all alarms for event
            new_event['alarms'].append(new_timestamp)

            # Clean list of timestamps to copy to
            new_timestamps = []
            initial_timestamps = len(new_event['timestamps'])

            # For all event timestamps within time_span of new_timestamp plus reset_time
            counter = 0
            min_stamp = new_timestamp - new_alert['time_span']
            max_stamp = new_timestamp + new_alert['reset_time']
            while counter < len(new_event['timestamps']):
                # If this timestamp falls outside the alarm window
                if new_event['timestamps'][counter] > max_stamp or new_event['timestamps'][counter] < min_stamp:
                    # Add it to list of clean timestamps
                    new_timestamps.append(new_event['timestamps'][counter])

                # Increment counter to check next value
                counter = counter + 1

            # Replace timestamps with trimmed list of timestamps
            new_event['timestamps'] = new_timestamps
            self.logger.debug("Trimmed %i timestamps after alert generation", initial_timestamps - len(new_timestamps))
            #self.logger.debug(f"Event is now {new_event}")

        # Return message and cleaned up event
        return message, new_event


    def email_alert(self, recipient, message):
        """
        Send a given message to the recipent
        """

        # Convert comma separated string to list
        recipients = recipient.split(',')

        self.logger.debug("Sending email to %s: %s", recipient, message.as_string())

        # If no encryption should be used
        if not self.encryption:
            try:
                server = smtplib.SMTP(self.smtp_server, self.port)

                # If a username and password have been supplied
                if self.password and len(self.sender) > 0:
                    # Authenticate in cleartext
                    server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipients, msg=message.as_string())
                server.quit()
                return True
            except Exception as e:
                self.logger.error("Failed to send cleartext message : %s", e)
                return False

        # Disable certificate verification if needed
        if self.trust_certificate:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()

        # Handle SSL encrypted SMTP
        if self.encryption.lower() == "ssl":

            # Try to setup a secure connection using SSL
            try:
                server = smtplib.SMTP_SSL(self.smtp_server, self.port, context=context)
                server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipients, msg=message.as_string())
                server.quit()
                return True
            except Exception as e:
                self.logger.error("SMTP over SSL issue : %s", e)
                # Secure connection failure, do not send email
                return False

        # Handle STARTTLS encrypted SMTP
        elif self.encryption.lower() == "starttls":

            # Try to setup a secure connection using STARTTLS
            try:
                server = smtplib.SMTP(self.smtp_server, self.port, context)
                server.starttls(context=context)
                server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipients, msg=message.as_string())
                server.quit()
                return True
            except Exception as ex:
                self.logger.error("SMTP over starttls issue : %s", ex)
                # Secure connection failure, do not send email
                return False

        # Invalid encrypt setting
        else:
            self.logger.error("Invalid setting for encryption : %s", self.encryption)
            return False


    def load_events(self):
        """
        Load events from disk and purge older timestamps
        """

        try:
            # If state_db exists
            if os.path.exists(self.state_db):
                # If state_db isn't readable
                if not os.access(self.state_db, os.R_OK):
                    self.logger.error("%s exists but is unreadable", self.state_db)
                    return False
                # If state file exists but isn't writable
                if not os.access(self.state_db, os.W_OK):
                    self.logger.error("%s exists but is not writable", self.state_db)
                    return False
            else:
                # Create empty state file if it doesn't exist
                fp = open(self.state_db, "bw")
                fp.flush()
                fp.close()
                return True
        except Exception as ex:
            self.logger.error("Error accessing state_db (%s) : %s", self.state_db, ex)
            return False

        # Ensure state database isn't empty
        if os.path.getsize(self.state_db) == 0:
            self.logger.info("No events to load from %s", self.state_db)
            return True

        # Read events from file and load them with pickle
        try:
            f = open(self.state_db, 'rb')
            self.events = pickle.load(f)
            f.flush()
            f.close()
        except Exception as ex:
            self.logger.error("Unable to load events from %s : %s", self.state_db, ex)
            return False

        # Internal counters
        alarm_counter = 0
        purged_timestamps = 0
        purged_alarms = 0
        purge_list = {}
        purge_events = []

        # Calculate time delta for maximum age of events to track
        current_time = datetime.datetime.utcnow()
        past_time = datetime.timedelta(hours=self.stale_hours)
        limit = int((current_time - past_time).timestamp())

        # Loop through every event from state_db and check timestamps against limit
        for category in self.events:

            # List of events that can be purged
            purge_events = []

            for event in self.events[category]:

                # Timestamps to keep
                new_timestamps = []

                # Alarms to keep
                new_alarms = []

                # Loop through every timestamp and remove ones past the limit
                for timestamp in self.events[category][event]['timestamps']:
                    # Compare each timestamp against limit
                    if timestamp >= limit:
                        new_timestamps.append(timestamp)
                    else:
                        purged_timestamps = purged_timestamps + 1

                # Loop through every alarm and remove ones past the limit
                for alarm in self.events[category][event]['alarms']:
                    # Compare each alarm against limit
                    if alarm >= limit:
                        new_alarms.append(alarm)
                        alarm_counter = alarm_counter + 1
                    else:
                        purged_alarms = purged_alarms +1

                # Purge event if it has no timestamps or alarms
                if not new_timestamps and not new_alarms:
                    purge_events.append(event)

                else:
                    # Replace timestamps with new list rather than potentially performing multiple pop() operations
                    self.events[category][event]['timestamps'] = new_timestamps
                    self.events[category][event]['alarms'] = new_alarms

                    #self.logger.debug(f"Alert {category} for key {event} triggered on: {new_alarms}")

            # Track which events should be purged
            purge_list[category] = purge_events

        # Purge keys and associated events from state that are no longer needed
        for category in purge_list:
            for event in purge_list[category]:
                self.logger.debug(f"Purging key {event} in category {category} due to age")
                self.events[category].pop(event)

        # Compile statistics of internal state for debug output
        timestamp_count = 0
        events_count = 0
        alarm_count = 0

        # Count events and timestamps in events
        for category in self.events:
            for event in self.events[category]:
                events_count = events_count + 1
                timestamp_count = timestamp_count + len(self.events[category][event]['timestamps'])
                alarm_count = alarm_count + len(self.events[category][event]['alarms'])

        self.logger.info("Imported %i events with %i timestamps (%i timestamps and %i alerts discarded due to age) with %i alarms",\
                         events_count, timestamp_count, purged_timestamps, purged_alarms, alarm_count)

        self.logger.debug(f"Imported:\n{self.events}")

        return True

class StatsParser(syslogng.LogParser):
    """
    syslog-ng parser for handling internal statistics messages
    """

    def init(self, options):
        """
        This method is called at initialization time
        Should return false if initialization fails
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('StatsParser')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "StatsParser",
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

        self.logger.debug("Starting syslog-ng stats parser")

        # Ensure event_regex parameter is defined
        event_regex = r"\s(processed|dropped|queued|memory_usage)='([\w\.]+?)\(([\w\-\.]+)#?(.*?)\)=(\d+)'"
        if "event_regex" in options:
            event_regex = options["event_regex"]
        self.logger.debug("Event regex set to %s", event_regex)

        # Ensure ip_regex parameter is defined
        ip_regex = r"s_(\w+)[-_]+(\d+)[_-](\d+)-(\w+)"
        if "ip_regex" in options:
            ip_regex = options["ip_regex"]
        self.logger.debug("IP regex set to %s", ip_regex)

        # Ensure filters parameter is defined
        self.filters = "di_config_change,di_internal_alert,di_messages,di_class_violation,di_ssb,di_local,ds_local,ds_center,dst.file,dst.program,dst.logstore,dst.file,center,src.program,src.facility,src.host,src.internal,src.journald,src.severity,src.sender,si.local,si_local,si.internal,internal_source,internal_queue_length,localhost,msg_clones,payload_reallocs,scratch_buffers_count,scratch_buffers_bytes,sdata_updates,tag,license_host_usage,license_monthly_consumed_hosts".split(',')
        if "filters" in options:
            self.filters = options["filters"].split(',')
        self.logger.debug("Statistic filters set to : %s", self.filters)

        # Check if alerting should be enabled
        self.alert_log = False
        if "alert_log" in options:
            try:
                self.alert_log = open(options["alert_log"], "+a")
                self.syslog_hosts = {}
                self.logger.info("Alerts will be logged to %s", options["alert_log"])
            except Exception as ex:
                self.logger.error("Unable to write alerts to %s : %s", options["alert_log"], ex)

        # Check if alert_filter parameter is defined
        self.alert_filter = "license_host_usage,license_monthly_consumed,memory_usage".split(',')
        if "alert_filter" in options:
            self.alert_filter = options["alert_filter"].split(',')
        self.logger.debug("Alert filters set to : %s", self.alert_filter)

        # Compile regex for performance
        try:
            self.event_regex = re.compile(event_regex)
            self.ip_regex = re.compile(ip_regex)
        except Exception as ex:
            self.logger.error("Unable to compile regular expression : %s", ex)

        return True

    def deinit(self):
        """
        Flush log file to disk
        """

        if self.alert_log:
            try:
                self.alert_log.close()
            except Exception as ex:
                self.logger.error("Unable to flush alert_log : %s", ex)
                return False
        return True

    def parse(self,log_message):
        """
        Parse out syslog-ng stats messages to extract metrics and generate alerts if needed
        """

        # Set values from log_message
        timestamp = log_message['S_ISODATE']
        message = log_message['MESSAGE']
        host = log_message['HOST']

        # Convert bytes to strings if needed
        if isinstance(timestamp, bytes):
            timestamp = timestamp.decode("utf-8")
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        if isinstance(host, bytes):
            host = host.decode("utf-8")

        # Extract all metrics from a syslog-ng stats message
        metrics = self.event_regex.findall(message)

        if not metrics:
            self.logger.debug("No valid metrics found in %s", message)
            self.logger.debug("Using a filter before this parser such as:\nfilter f_stats { message('^Log statistics'); }; \nis recommended")
            return False

        # Initialize list of keys
        keys = {}

        # Loop through all metrics
        for metric in metrics:

            # Standardize name of metric
            key = f"{metric[2]}-{metric[0]}"

            # Cleanup duplicate d_ or s_
            key = key.replace(".d_d_", ".d_")
            key = key.replace(".s_s_", ".s_")

            # Remove IP octet from source if present
            match = self.ip_regex.search(key)
            if match:
                key = f"{match.group(1)}-{match.group(2)}-{match.group(4)}"

            # Filter out metrics we don't care about
            if self.filters:
                if metric[1] not in self.filters and metric[2] not in self.filters:
                    if key not in keys:
                        keys[key] = metric[4]

            # If there are no filters defined include everything
            else:
                if key not in keys:
                    keys[key] = metric[4]

        # Rewrite message to key=value format
        new_message = ""
        for key, value in keys.items():
            new_message = new_message + f' {key}={value}'
        log_message['MESSAGE'] = new_message

        # Check against previous metrics if alerting is enabled
        if self.alert_log:

            # Start with empty alert value
            alerts = ""

            # Check if we've seen this host before
            if host in self.syslog_hosts:

                # Check if we've seen this key before
                for key, value in self.syslog_hosts[host].items():

                    # Check against previous value
                    if key in keys and key not in self.alert_filter:

                        # Convert to int for comparison purposes
                        oldvalue = int(value)
                        newvalue = int(keys[key])

                        # For dropped we want the number to be unchanged
                        if "dropped" in key:
                            if newvalue > oldvalue:
                                try:
                                    self.alert_log.write(f'WARN {timestamp} - {key} is increasing on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'ALERT - {key} is increasing on {host} ({oldvalue}=>{newvalue}) '

                        # For queued we want the number to be lower
                        elif "queued" in key:
                            if newvalue > oldvalue:
                                try:
                                    self.alert_log.write(f'INFO {timestamp} - {key} is increasing on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'WARN - {key} is increasing on {host} ({oldvalue}=>{newvalue}) '

                        # For processed we want the number to be higher
                        elif "processed" in key:
                            if newvalue == oldvalue:
                                try:
                                    self.alert_log.write(f'WARN {timestamp} - {key} is unchanged on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'ALERT - {key} is unchanged on {host} ({oldvalue}=>{newvalue}) '

            # Keep track or results for this host for next pass
            self.syslog_hosts[host] = keys

            # Set new ALERTS macro for message
            log_message['ALERTS'] = alerts

            # Flush alerts to disk
            self.alert_log.flush()
            os.fsync(self.alert_log.fileno())

        return True
