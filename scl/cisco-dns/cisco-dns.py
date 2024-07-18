"""
Copyright (c) 2024 Novacoast

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)

Syslog-ng python source for Cisco-DNS
https://docs.umbrella.com/deployment-umbrella/docs/cisco-managed-s3-bucket

Additional documentation available at:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.36/administration-guide/25#TOPIC-1768580
"""

import gzip
import os
from datetime import datetime, timezone, timedelta
import logging
import base64
from collections import deque
from botocore.config import Config
import urllib3
import boto3

import syslogng

class Dns(syslogng.LogFetcher):
    """
    Class for python syslog-ng fetch-style log source
    """

    # Initialize Cisco-DNS driver
    def init(self, options):
        """
        Initialize Cisco-DNS driver options
        (optional for Python LogFetcher)
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('Cisco-DNS')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "Cisco-DNS Driver",
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

        # Whether this is our first run or not
        self.first_run = True

        # Tracker for whether new archives were processed
        self.new_archives = False

        # Initialize empty list of log messages
        self.logs = []

        # Ensure aws_access_key_id parameter is defined
        if "aws_access_key_id" in options:
            self.aws_access_key_id = options["aws_access_key_id"]
            self.logger.debug("Initializing Cisco-DNS driver with aws_access_key_id %s", self.aws_access_key_id)
        else:
            self.logger.error("Missing aws_access_key_id configuration option")
            return False

        # Ensure client_secret parameter is defined
        if "aws_secret_access_key" in options:
            try:
                self.aws_secret_access_key = base64.b64decode(options["aws_secret_access_key"]).decode("utf-8")
            except UnicodeDecodeError:
                self.logger.error("Invalid aws_secret_access_key provided (did you remember to base64 encode it?)")
                return False
        else:
            self.logger.error("Missing aws_secret_access_key configuration option")
            return False

        # Ensure bucket parameter is defined
        if "bucket" in options:
            self.bucket = options["bucket"]
            self.logger.debug("Initializing Cisco-DNS with bucket %s", self.bucket)
        else:
            self.logger.error("Missing bucket configuration option")
            return False

        # Ensure backfill_minutes parameter is defined
        if "backfill_minutes" in options:
            try:
                self.backfill_minutes = int(options["backfill_minutes"])
                self.logger.debug("Initializing Cisco-DNS with backfill_minutes %s", self.backfill_minutes)
            except Exception:
                self.logger.warning("Invalid value for backfill_minutes specified : %s", options["backfill_minutes"])
                self.backfill_minutes = 5
        else:
            self.backfill_minutes = 5

        # Warn for large values of backfill_minutes
        if self.backfill_minutes > 60:
            self.logger.warning("%i is larger than recommended for backfill_minutes and can cause performance issue", self.backfill_minutes)

        # Setup blocklist if specified
        self.blocks = []
        if "blocklist" in options:

            if os.path.isfile(options["blocklist"]):
                self.logger.debug("Loading %s as blocklist", options["blocklist"])

                # Read in the contents of the existing blocklist
                try:
                    filebuffer = open(options["blocklist"], 'r', encoding="UTF-8")
                    lines = filebuffer.readlines()
                    for line in lines:
                        self.logger.debug("Will ignore archives from org %s", line.rstrip())
                        self.blocks.append(line.rstrip())
                    filebuffer.close()

                except Exception as ex:
                    self.logger.warning("Unable to read blocklist %s", options["blocklist"])
                    self.logger.warning(ex)
            
            else:
                self.logger.error("Blocklist file %s does not exist", options["blocklist"])

        # Size of internal deque list for tracking processed archives
        if "deque_length" in options:
            try:
                self.deque_length = int(options["deque_length"])
                self.logger.debug("Initializing Cisco-DNS with deque_length %s", self.deque_length)
            except Exception:
                self.logger.warning("Invalid value for deque_length specified : %s", options["deque_length"])
                self.deque_length = 10000
        else:
            self.deque_length = 10000

        # Size of written deque list fo tracking processed archives
        if "state_size" in options:
            try:
                self.state_size = int(options["state_size"])
                self.logger.debug("Initializing Cisco-DNS with state_size %s", self.state_size)
            except Exception:
                self.logger.warning("Invalid value for state_size specified : %s", options["state_size"])
                self.state_size = 10000
        else:
            self.state_size = 10000

        # Limit for internal memory buffer for processed events
        if "buffer_size" in options:
            try:
                self.buffer_size = int(options["buffer_size"])
                self.logger.debug("Initializing Cisco-DNS with buffer_size %s", self.buffer_size)
            except Exception:
                self.logger.warning("Invalid value for buffer_size specified : %s", options["buffer_size"])
                self.buffer_size = 10000000
        else:
            self.buffer_size = 10000000

        # Set ssl_verify to false only if specified
        self.ssl_verify = True
        if "ssl_verify" in options:
            if options["ssl_verify"].lower() == "false":
                self.ssl_verify = False
                urllib3.disable_warnings()
                self.logger.info("Disabling SSL certificate verification for ssl_verify:%s", self.ssl_verify)
            elif os.path.exists(options["ssl_verify"]):
                self.ssl_verify = options["ssl_verify"]
                self.logger.info("Using %s as CA certificate", self.ssl_verify)
            else:
                self.logger.warning("Invalid value specified for ssl_verify: %s", options["ssl_verify"])

        # Set proxy if specified
        self.proxy = {}
        if "proxy" in options:
            self.proxy = {
                'http':options["proxy"],
                'https':options["proxy"]
            }

        # Setup persist_name with defined persist_name or use bucket if possible
        try:
            self.persist_name
        except:
            self.persist_name = "cisco-dns-%s" % self.bucket

        # Initialize persistence
        self.logger.debug("Initializing driver with persist_name %s", \
                self.persist_name)

        # Convert start_time to Cisco-DNS format at current time
        self.start_time = datetime.strftime(datetime.now(timezone.utc), "%Y-%m-%d %H:%M:%S+00:00")

        # Load last_read from persistence and default to self.backfill_minutes ago
        self.persist = syslogng.Persist(persist_name=self.persist_name, defaults={"last_read": self.start_time})

        # Setup persistence values and validate them
        try:
            self.logger.debug("Persistence was set to %s", self.persist["last_read"])

            # Ensure the last_read time is a valid datetime format
            valid_datetime = datetime.strptime(self.persist["last_read"], "%Y-%m-%d %H:%M:%S+00:00")
            self.start_time = datetime.strftime(valid_datetime, "%Y-%m-%d %H:%M:%S+00:00")

            # Warn if persistence is too far back
            delta = datetime.utcnow() - valid_datetime
            self.logger.debug("Persistence is back %s ago", delta)

        except:
            # If last_read isn't valid, reset to initial_hours ago
            self.logger.error("Invalid last_read (%s) detected in persistence, resetting to %s minutes ago", \
                self.persist["last_read"], self.backfill_minutes)

        # Track length of search window
        go_back = timedelta(minutes=self.backfill_minutes + 1)
        go_back_time = datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S+00:00") - go_back
        self.search_window = datetime.utcnow() - go_back_time

        # Use disk buffer if configured
        self.disk_buffer = ""
        if "disk_buffer" in options:

            # Check if this is a valid file or directory
            if os.path.isfile(options["disk_buffer"]):
                self.disk_buffer = options["disk_buffer"]
            elif os.path.isdir(options["disk_buffer"]):
                self.disk_buffer = options["disk_buffer"] + "/buffer"

            self.logger.debug("Will use %s as disk buffer", self.disk_buffer)

            # Read in the contents of the existing buffer to memory if there are any
            try:
                filebuffer = open(self.disk_buffer, 'r', encoding="UTF-8")
                lines = filebuffer.readlines()
                for line in lines:
                    self.logs.append(line.rstrip())

                filebuffer.close()

                self.logger.info("Loaded %i events from disk buffer %s", len(self.logs), self.disk_buffer)

                # Delete the buffer after it's been loaded into memory
                try:
                    os.remove(self.disk_buffer)

                except Exception as ex:
                    self.logger.error("Unable to delete buffer %s", self.disk_buffer)
                    self.logger.error(ex)
                    return False

            except FileNotFoundError:
                self.logger.debug("Buffer file %s does not exist", self.disk_buffer)

            except Exception as ex:
                self.logger.warning("Unable to read buffer %s", self.disk_buffer)
                self.logger.warning(ex)

        # Use state file if configured
        self.state = deque(maxlen=self.deque_length)
        self.state_file = ""
        if "state_file" in options:

            # Check if this is a valid file or directory
            if os.path.isfile(options["state_file"]):
                self.disk_buffer = options["state_file"]
            elif os.path.isdir(options["state_file"]):
                self.disk_buffer = options["state_file"] + "/state"

            self.state_file = options["state_file"]
            self.logger.debug("Will use %s as state file", self.state_file)

            # Read in the contents of the existing state_file to memory if there are any
            try:
                filebuffer = open(self.state_file, 'r', encoding="UTF-8")
                lines = filebuffer.readlines()

                # Make sure we have enough internal state to read in state file
                if self.state_size < len(lines):
                    self.state = deque(maxlen=len(lines))

                for line in lines:
                    self.state.append(line.rstrip())

                filebuffer.close()
                self.logger.info("Loaded %i previously processed paths from state_file %s", len(self.state), self.state_file)

            except FileNotFoundError:
                self.logger.debug("State file %s does not exist", self.state_file)

            except Exception as ex:
                self.logger.warning("Unable to read state file %s", self.state_file)
                self.logger.warning(ex)

        else:
            if "backfill_minutes" in options:
                self.logger.critical("No state_file specified and backfill_minutes is set, log duplication likely on restart")
            else:
                self.logger.warning("No state_file specified, log duplication may occur during a restart/reload operation")

        return True


    def process_message(self, log):
        """
        Parse a single log message and extrace timestamp and program field
        """

        message = log
        org = ""

        try:
            # Get org name from first value
            fields = log.split(',', 1)
            org = fields[0]
            message = fields[1]

            # Get timestamp from second value
            timestamp = datetime.now(timezone.utc)
            fields = message.split(',', 1)
            stringstamp = fields[0].lstrip('\"').rstrip('\"')
            try:
                timestamp = datetime.strptime(stringstamp, "%Y-%m-%d %H:%M:%S")
            except Exception as ex:
                try:
                    timestamp = datetime.strptime(stringstamp, "%Y-%m-%d %H:%M:%S+00:00")
                except Exception as ex2:
                    self.logger.debug("Invalid timestamp format (%s): %s", stringstamp, ex2)

        except Exception as ex:
            self.logger.warning("Event (%s) does not appear to be csv format: %s", log, ex)

        # Create syslogng LogMessage with fields
        msg = syslogng.LogMessage(message)
        msg["PROGRAM"] = "Cisco-DNS"
        msg["ORG"] = org
        msg.set_timestamp(timestamp)

        return msg


    def fetch(self):
        """
        Return a single log message by either pulling from the internal dict or pulling from the Umbreall S3 bucket
        """

        # Retrieve log messages from memory if present
        if len(self.logs) > 0:
            try:
                log = self.logs.pop()
                msg = self.process_message(log)
                return syslogng.LogFetcher.FETCH_SUCCESS, msg
            except Exception as ex:
                self.logger.error("Error processing in memory log : %s", ex)
                return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Error processing log"

        # Reduce backfill_minutes after first run for performance if needed
        if self.backfill_minutes > 60 and not self.first_run:
            self.backfill_minutes = 60

        # Start search window back backfill_minutes ago
        go_back = timedelta(minutes=self.backfill_minutes)
        go_back_time = datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S+00:00") - go_back
        fetch_start = datetime.strftime(go_back_time, "%Y-%m-%d %H:%M:%S+00:00")
        self.logger.debug("Starting fetch window at %s", fetch_start)

        # Check search window
        if datetime.utcnow() - go_back_time > self.search_window + timedelta(minutes=1):
            self.logger.warning("Length of search window is increasing (%s > %s)", datetime.utcnow() - go_back_time, self.search_window)
            self.logger.info("Consider decreasing fetch-no-data-delay or increasing CPU resources")

        self.search_window = datetime.utcnow() - go_back_time

        # Retrieve the list of objects newer than start_time from this bucket
        try:
            s3_paginator = self.s3_client.get_paginator('list_objects_v2')
            s3_iterator = s3_paginator.paginate(Bucket=self.bucket)
            filtered_iterator = s3_iterator.search(
                "Contents[?to_string(LastModified)>='\"%s\"'].Key" % fetch_start
            )
        except Exception as ex:
            self.logger.error("Unable to retrieve list of new objects from %s : %s", self.bucket, ex)
            return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Failed to retrieve archive list"

        # Build out list of archives
        archives = []
        for key_data in filtered_iterator:
            # Only look at .csv.gz files that we haven't processed already
            if ".csv.gz" in key_data and key_data not in self.state and key_data not in archives:
                archives.append(key_data)

        # There are more archives in a single batch than were in the state file
        if len(archives) > self.state.maxlen and self.first_run:
            self.logger.info("%i archives to process but state file only tracks %i (%i loaded)", \
                                len(archives), self.state.maxlen, len(self.state))
            self.logger.warning("Potentially duplicated log archives (%i archives to process)", len(archives))

        # There are more archives in a single batch than we can internally track
        if len(archives) > self.state.maxlen:

            self.logger.warning("There are %i archives to process, growing internal state size (%i) to match", len(archives), self.state.maxlen)

            # Create new deque to hold all results
            state_copy = deque(maxlen=len(archives))

            # Copy everything over from existing deque
            while len(self.state) > 0:
                state_copy.append(self.state.popleft())
            self.state = state_copy

        # Check each archive to see if it needs to be processed
        while len(archives) > 0:

            # New archives to process
            self.new_archives = True

            # Extract path and filename if possible
            archive_name = archives.pop()
            filename = archive_name
            try:
                #tenant = elements[0]
                elements = archive_name.split('/')
                filename = elements.pop()
                org = elements[1]
            except Exception as ex:
                self.logger.warning("%s not under standard path with tenant and org (%s)", filename, archive_name)
                #tenant = ""
                org = ""

            # Do not process archives from a blocked org
            if org in self.blocks:
                self.logger.debug("Skipping %s since org %s is in blocklist", archive_name, org)
            else:
                # Try to retrieve s3 object
                try:
                    archive = self.s3_client.get_object(
                        Bucket=self.bucket,
                        Key=archive_name
                    )

                except Exception as ex:
                    self.logger.error("Unable to retrieve %s from %s : %s", archive_name, self.bucket, ex)
                    return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Failed to retrieve archive"
                
                # Uncompress gzip contents and feed into self.logs
                try:
                    contents = archive['Body'].read()
                    uncompressed = gzip.decompress(contents).decode('utf-8')

                    old_log_count = len(self.logs)

                    # Add valid lines to list of logs to process
                    for line in uncompressed.split('\n'):
                        if len(line) > 10:
                            # Include metadata from file path in log entry
                            self.logs.append(org + "," + line)

                    self.logger.debug("Extracted %i logs from %s (%i archives remaining)", \
                                        len(self.logs) - old_log_count, archive_name, len(archives))

                    # Add archive name to list of processed files in state
                    self.state.append(archive_name)

                except Exception as ex:
                    self.logger.error("Failed to decompress and extract logs from %s : %s", archive_name, ex)
                    return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Log extraction failure"

                # If we have more messages to process than should be in the memory buffer
                if len(self.logs) >= self.buffer_size:
                    break

        # If we have any logs to process
        if len(self.logs) > 0:
            log = self.logs.pop()
            msg = self.process_message(log)
            self.first_run = False
            return syslogng.LogFetcher.FETCH_SUCCESS, msg

        # Update last run time if there were no new archives to process
        self.logger.debug("No new logs available")
        self.start_time = datetime.strftime(datetime.now(timezone.utc), "%Y-%m-%d %H:%M:%S+00:00")
        self.persist["last_read"] = self.start_time

        # Flush list of processed archives to file
        self.flush_state(force=False)
        return syslogng.LogFetcher.FETCH_NO_DATA, "No new Cisco-DNS events available"


    def request_exit(self):
        """
        Begin shutdown process for driver
        """

        self.logger.info("Shutdown requested with %i events in memory buffer", len(self.logs))
        self.exit = True


    def open(self):
        """
        Initialize s3_client
        """

        self.logger.info("Initializing s3 client")

        # Initialize botocore Config
        if len(self.proxy) > 0:
            config = Config(
                proxies=self.proxy,
                connect_timeout=30, 
                read_timeout=30,
                retries={'max_attempts': 3}
        )
        else:
            config = Config(
                connect_timeout=30, 
                read_timeout=30,
                retries={'max_attempts': 3}
            )

        try:
            # Use default of verifying certificate
            if self.ssl_verify is True:
                self.s3_client = boto3.client('s3',
                                aws_access_key_id=self.aws_access_key_id,
                                aws_secret_access_key=self.aws_secret_access_key,
                                config=config
                                )
            # Use path to CA certificate
            elif os.path.exists(self.ssl_verify):
                self.s3_client = boto3.client('s3',
                                aws_access_key_id=self.aws_access_key_id,
                                aws_secret_access_key=self.aws_secret_access_key,
                                config=config,
                                verify=self.ssl_verify
                                )
            # Disable certificate verification
            else:
                self.s3_client = boto3.client('s3',
                                aws_access_key_id=self.aws_access_key_id,
                                aws_secret_access_key=self.aws_secret_access_key,
                                config=config,
                                verify=False
                                )
        except Exception as ex:
            self.logger.error("Error initializing s3 client: %s", ex)
            return False

        # No errors
        return True


    def deinit(self):
        """
        Flush in-memory logs to buffer file if configured during shutdown
        """

        self.logger.info("Deinitializing with %i events in memory buffer", len(self.logs))

        # Track whether clean exit is possible
        clean = True

        # If there are events still in memory
        if self.logs:

            # Check if disk buffer is configured
            if self.disk_buffer:

                # Flush memory buffer to disk buffer
                self.logger.info("Flushing %i events to disk buffer %s", \
                    len(self.logs), self.disk_buffer)

                try:
                    with open(self.disk_buffer, 'a') as filebuffer:

                        # Loop through every entry in self.logs and delete as we go
                        while self.logs:
                            message = self.logs.pop()
                            filebuffer.write(message + '\n')

                # Write to file buffer error
                except IOError as ex:
                    self.logger.error("Unable to flush memory to disk buffer at %s : %s", self.disk_buffer, ex)
                    clean = False

                # Catch general exception
                except Exception as ex:
                    self.logger.error(ex)
                    clean = False

            # Warn that events will be lost because no file buffer is present
            else:
                self.logger.error("Closing connection but %i events will be lost in memory buffer", len(self.logs))
                self.logger.error("Please configure the disk_buffer option in the future to prevent loss of events")
                clean = False

        # No events in memory, ready for clean shutdown
        else:
            self.logger.info("No events to flush from memory")

        # If there are still events in memory or an error ocurred
        if not clean and self.state_file:
            self.logger.warning("Will not flush %i archive names to state file due to %i remaining events in memory", \
                                len(self.state), len(self.logs))

        else:
            # Notify if there's a chance that state file won't capture all recent archives
            if len(self.state) > self.state.maxlen and self.state_file:
                self.logger.info("At least %i archives processed but only flushing %i to %s on shutdown", len(self.state), self.state.maxlen, self.state_file)

            self.flush_state(force=True)


    def flush_state(self, force):
        """
        Write state to file
        """

        # Only flush to disk if force==True or we have new archives since last flush
        if force or self.new_archives:

            # Only flush if we have a state_file to flush to
            if self.state_file:
                try:
                    filebuffer = open(self.state_file, 'w', encoding="UTF-8")

                    if len(self.state) < self.state.maxlen:
                        self.logger.debug("Flushing %i archive names to %s", len(self.state), self.state_file)
                        for item in list(self.state):
                            filebuffer.write(item + "\n")
                    else:
                        # If there are more items in self.state than will be written to the state file get the offset
                        counter = len(self.state) - self.state_size
                        self.logger.debug("Flushing %i out of %i archive names to %s", \
                                        self.state_size, self.state.maxlen, self.state_file)
                        # Output contents of self.state from starting offset or 0 if there's less than self.state.maxlen
                        while counter < len(self.state):
                            filebuffer.write(self.state[counter] + "\n")
                            counter = counter + 1

                    filebuffer.close()

                    self.new_archives = False

                except Exception as ex:
                    self.logger.error("Unable to flush state to %s : %s", self.state_file, ex)

            else:
                self.logger.warning("No state_file configured, the list of already processed archives will be lost on shutdown")
                if self.backfill_minutes > 0:
                    self.logger.warning("Without state_file and %i backfill_minutes, log duplication is likely", self.backfill_minutes)

