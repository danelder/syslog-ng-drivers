#!/usr/bin/env python3

"""
Copyright (c) 2024 Novacoast

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)

Dynamic syslog-ng configuration script for eventhub-fanout
"""

import argparse
import ipaddress
import os
import configparser
from pathlib import Path
import netifaces as ni
from netifaces import AF_INET

def sanitize(content):
    """
    Filter out characters that would break syslog-ng configuration
    """

    return (content.translate({ord(i): None for i in '\'\"\r'}))


def interface_address(interface):
    """
    Return an IPv4 address or False if interface doesn't exist and isn't already an IPv4 address
    """

    ip_address = False

    # Check if this is already an IPv4 address
    try:
        ipaddress.ip_address(interface)
        return interface
    except ValueError:
        pass

    # Get IPv4 address of interface if possible
    try:
        ip_address = ni.ifaddresses(interface)[AF_INET][0]['addr']
    except Exception:
        pass

    return ip_address


# Debug log file
debug_log = "/tmp/eventhub-destinations.log"

# Worker limits and tracking
MAX_WORKERS = 256
total_workers = 0

# Timestamp format
date_format = "$YEAR$MONTH$DAY"

# Global parser for access by functions
parser = argparse.ArgumentParser(description='This is a simple tool to convert the one line dictionary into eventhub compatible syslog-ng destinations.')
parser.add_argument('--debug', help='Enable debug mode', action="store_true")
args = parser.parse_args()

# Enable debug logging if requested
if args.debug:
    try:
        debug = open(debug_log,"w")
        debug.write("Initializing debug log\n")
    except PermissionError as pe:
        print(f"Permission denied while writing to {debug_log}, please check permissions and try again")
        exit(1)
    except Exception as ex:
        print(f"Unable to write to {debug_log} : {ex}")
        exit(1)

# Capture environment variables for syslog-ng configuration
confgen_url = sanitize(os.environ.get('confgen_url', ""))
confgen_batch_lines = sanitize(os.environ.get('confgen_batch_lines', "1000"))
confgen_batch_bytes = sanitize(os.environ.get('confgen_batch_bytes',"1023kb"))
confgen_batch_timeout = sanitize(os.environ.get('confgen_batch_timeout', "10000"))
confgen_headers = os.environ.get('confgen_headers', "")
confgen_tls_verify = sanitize(os.environ.get('confgen_tls_verify', "yes"))
confgen_auth_token = sanitize(os.environ.get('confgen_auth_token', ""))
confgen_ini = sanitize(os.environ.get('confgen_ini', "/opt/syslog-ng/etc/eventhub.ini"))
confgen_address = sanitize(os.environ.get('confgen_address', "0.0.0.0"))
confgen_keyfile = sanitize(os.environ.get('confgen_keyfile', ""))
confgen_certfile = sanitize(os.environ.get('confgen_certfile', ""))
confgen_rcvbuf = sanitize(os.environ.get('confgen_rcvbuf', "20971520"))
confgen_fetch_limit = sanitize(os.environ.get('confgen_fetch_limit', "10000"))
confgen_mem_buf = sanitize(os.environ.get('confgen_mem_buf', "10000"))
confgen_disk_buf = sanitize(os.environ.get('confgen_disk_buf', "10485760"))
confgen_disk_dir = sanitize(os.environ.get('confgen_disk_dir', "/tmp"))
confgen_local_log_path = sanitize(os.environ.get('confgen_local_log_path', ""))
confgen_container = sanitize(os.environ.get('confgen_container', ""))

# Diagnostic output if needed
if args.debug:
    debug.write(f"confgen_url environment variable is {confgen_url}\n")
    debug.write(f"confgen_batch_lines environment variable is {confgen_batch_lines}\n")
    debug.write(f"confgen_batch_bytes environment variable is {confgen_batch_bytes}\n")
    debug.write(f"confgen_batch_timeout environment variable is {confgen_batch_timeout}\n")
    debug.write(f"confgen_headers environment variable is {confgen_headers}\n")
    debug.write(f"confgen_auth_token environment variable is {confgen_auth_token}\n")
    debug.write(f"confgen_tls_verify environment variable is {confgen_tls_verify}\n")
    debug.write(f"confgen_ini environment variable is {confgen_ini}\n")
    debug.write(f"confgen_address environment variable is {confgen_address}\n")
    debug.write(f"confgen_keyfile environment variable is {confgen_keyfile}\n")
    debug.write(f"confgen_certfile environment variable is {confgen_certfile}\n")
    debug.write(f"confgen_rcvbuf environment variable is {confgen_rcvbuf}\n")
    debug.write(f"confgen_fetch_limit environment variable is {confgen_fetch_limit}\n")
    debug.write(f"confgen_mem_buf environment variable is {confgen_mem_buf}\n")
    debug.write(f"confgen_disk_buf environment variable is {confgen_disk_buf}\n")
    debug.write(f"confgen_disk_dir environment variable is {confgen_disk_dir}\n")
    debug.write(f"confgen_local_log_path environment variable is {confgen_local_log_path}\n")
    debug.write(f"confgen_container environment variable is {confgen_container}\n")

# Initialize empty dicts
country_list = {}
source_list = {}
body_formats = {}
destinations = ""

# Determine if we're running in a container
running_in_container = False
if confgen_container == "true":
    running_in_container = True

# Default address to bind to
global_address = "0.0.0.0"

# If we're not running in a container
if not running_in_container:
    # Resolve confgen_address value(s) to an IPv4 address if possible
    for value in confgen_address.split(','):
        address = interface_address(value)

        if address is not False:
            global_address = address
            break
# If we are running in a container, ensure confgen_local_log_path is set to /tmp
else:
    if confgen_local_log_path != "":
        confgen_local_log_path = "/tmp"

# Utilize ini style configuration files
parser = configparser.ConfigParser()

# Populate list of countries and workers for each
parser.read(confgen_ini)
try:
    countries = parser.items("Countries")
    for country, country_workers in countries:
        country_list[country.upper()] = int(country_workers)
except Exception as e:
    print(f"Unable to process Countries in {confgen_ini} : {e}")

# Check if auth token file exists
if not os.path.exists(confgen_auth_token):
    if args.debug:
        debug.write(f"{confgen_auth_token} does not exist, cannot read auth token")
    exit(1)

# Read auth token
try:
    with open(confgen_auth_token, "r") as file:
        # Extract auth token from file and remove newline
        auth_token = file.readline().replace("\n","")
except Exception as e:
    if args.debug:
        debug.write(f"Unable to read {confgen_auth_token} : {e}")
    exit(1)

# Set auth token in headers
confgen_headers = confgen_headers.replace("AUTH_TOKEN", auth_token)

# Populate list of templates for http body
try:
    templates = parser.items("Templates")
    for name, bformat in templates:
        body_formats[name] = bformat
except Exception as e:
    print(f"Unable to process Templates in {confgen_ini} : {e}")

# Check for too many workers being assigned in configuration
worker_count = 0
for configuration in parser.sections():
    # Ignore non-log path configurations
    if "Templates" in configuration or "Countries" in configuration:
        pass
    else:
        # Extract workers multiplier for source
        if "workers" in parser[configuration]:
            try:
                workers = float(parser[configuration]['workers'])
                # Ensure we have at least 1 worker
                if workers < 1:
                    workers = 1
            except:
                workers = 1
        else:
            workers = 1

        # Get workers assigned by country
        for country, country_workers in country_list.items():

            # Track total number of workers
            worker_count = worker_count + (workers * country_workers)

# Calculate the precentage to reduce worker counts by to stay under the limit of MAX_WORKERS
reduction_factor = 1
if worker_count > MAX_WORKERS:
    reduction_factor = (MAX_WORKERS - 1) / worker_count
    if args.debug:
        debug.write(f"{worker_count} workers set but limit is {MAX_WORKERS}\n")
        debug.write(f"Will use reduction factor of {reduction_factor:.2f} to scale down number of workers\n")

# Loop through configuration and extract relevent sections
for configuration in parser.sections():
    # Ignore non-log path configurations
    if "Templates" in configuration or "Countries" in configuration:
        pass
    else:
        # Extract source name and port
        try:
            source = configuration
            port = parser[configuration]['port']

        # This isn't a valid log flow
        except Exception as ex:
            print(f"Invalid configuration section {configuration} : {ex}")
            continue

        # Extract filter(s) from configuration
        if "filters" in parser[configuration]:
            filters = parser[configuration]['filters'].split(',')
        else:
            filters = {}

        # Set address to global_address by default
        address = global_address
            
        # Get source address to use if configured
        if not running_in_container:
            if "address" in parser[configuration]:
                for value in parser[configuration]['address'].split(','):

                    # Assign address if it resolves
                    if interface_address(value) is not False:
                        address = interface_address(value)

                        # Break out of loop once valid address is found
                        break

        # Extract workers multiplier for source
        if "workers" in parser[configuration]:
            try:
                workers = float(parser[configuration]['workers']) * reduction_factor
            except:
                if args.debug:
                    debug.write("Invalid worker multiplier (%s) for %s", parser[configuration]['workers'], source)
                workers = reduction_factor
        else:
            workers = reduction_factor

        # Extract template from configuration or use default if none is set
        if "template" in parser[configuration]:
            body_format_template = parser[configuration]['template']
        else:
            body_format_template = "default"

        # Extract rewrite rule from configuration if set
        if "rewrites" in parser[configuration]:
            rewrites = parser[configuration]['rewrites'].split(',')
        else:
            rewrites = {}

        # Extract remote destination from configuration if set
        if "destinations" in parser[configuration]:
            additional_destinations = parser[configuration]['destinations'].split(',')
        else:
            additional_destinations = False

        # Match body_format_template to body_format
        try:
            body_format = body_formats[body_format_template]
        except KeyError as ke:
            # Default message format if there is no match
            body_format = "\"${MESSAGE}\""

        # Check if local log path should be enabled for source
        local_log = False
        if "local_log" in parser[configuration]:
            if parser[configuration]['local_log'].lower() == "true":
                local_log = True

        # Construct syslog-ng destinations
        for country, country_workers in country_list.items():

            # Assign number of workers for this destination
            my_workers = workers * country_workers

            # Ensure there is always at least 1 worker
            if my_workers < 1:
                my_workers = 1

            destinations = f"""
destination d_{source}-{port}-{country} {{
    http(
        persist-name("persist-{source}-{port}-{country}")
        url("{confgen_url}/{source}/messages")
        method("POST")
        batch-lines({confgen_batch_lines})
        batch-bytes({confgen_batch_bytes})
        batch-timeout({confgen_batch_timeout})
        workers({int(my_workers)})
        disk-buffer(
            disk-buf-size({confgen_disk_buf})
            mem-buf-length({confgen_mem_buf})
            dir({confgen_disk_dir}/{source}-{port}-{country})
            reliable(no)
        )
        headers("{confgen_headers} {country.upper()}")
        body-suffix("\\n")
        body({body_format})
            tls(
                peer-verify({confgen_tls_verify})
            )
        );
}};
"""

            # Setup local logging destination if configured
            if confgen_local_log_path != "" and local_log:
                try:
                    os.mkdir(f"{confgen_local_log_path}/{source}")
                except FileExistsError:
                    # File already exists
                    pass
                except Exception as e:
                    print(f"Unable to create directory {confgen_local_log_path}/{source} : {e}")

                destinations = destinations + f"""
destination d_{source}-{port}-{country}_local {{
    file(
        "{confgen_local_log_path}/{source}/{date_format}-{country}-{source}.log"
        create-dirs(yes)
    );
}};            
"""

            # Track total workers
            total_workers = total_workers + int(my_workers)

            # Print configuration to syslog-ng
            print(destinations)

            if args.debug:
                debug.write(destinations)

        # Source definition
        source_definition = f"""
source s_{source} {{
    syslog(
        ip({address})
        port({port})
        transport("tls")
            tls(
                key-file("{confgen_keyfile}")
                cert-file("{confgen_certfile}")
                peer-verify(none)
            )
        log-fetch-limit({confgen_fetch_limit})
        so-rcvbuf({confgen_rcvbuf})
    );
}};
    """

        # Output configuration
        print(source_definition)

        if args.debug:
            debug.write(source_definition)

        # Generate log path with logic for routing based on country code
        paths = f"""
log {{
    source(s_{source});
"""

        # If there's a filter(s) defined
        if filters:
            for log_filter in filters:
                paths = paths + f"    filter({log_filter});\n"

        # If there's a rewrite rule(s) defined
        if rewrites:
            for rewrite in rewrites:
                paths = paths + f"    rewrite({rewrite});\n"

        # If there's an additional destination(s) defined
        if additional_destinations:
            for additional_destination in additional_destinations:
                paths = paths + f"    destination({additional_destination});\n"

        # Track number of countries that have been processed in list
        counter = 0
        final = ""
        first = ""

        # Loop through every country code
        for country, workers in country_list.items():
            counter += 1

            # Create destination definition
            destination = f"        destination(d_{source}-{port}-{country});"

            # Add local log path to destinations if configured
            if confgen_local_log_path != "" and local_log:
                destination = destination + f"\n        destination(d_{source}-{port}-{country}_local);"

            # If this is our first country code, use if
            if counter == 1:
                paths = paths + f"""    if (match('{country}' value('.SDATA.meta.country'))) {{
{destination}
        flags(flow-control);
    }}"""
                first = destination

            # If this our last country code (and there is more than 1 country code), include else
            elif counter == len(country_list) and len(country_list) > 1:
                paths = paths + f""" elif (match('{country}' value('.SDATA.meta.country'))) {{
{destination}
        flags(flow-control);
    }} else {{
{first}
        flags(flow-control);
    }}"""

            # If this isn't our first or last country code, use elif
            else:
                paths = paths + f""" elif (match('{country}' value('.SDATA.meta.country'))) {{
{destination}
        flags(flow-control);
    }}"""

        # Finalize paths
        paths = paths + ";\n};\n\n"

        # Print configuration output
        print(paths)

        if args.debug:
            debug.write(paths)

# Ensure we haven't exceeded that maximum number of workers
if total_workers >= MAX_WORKERS:
    print(f"ERROR - You have {total_workers} workers assigned but the maximum supported limit is {MAX_WORKERS}\n")
    print("Please reduce the number of workers assigned by country or by source multiplier and try again\n")
