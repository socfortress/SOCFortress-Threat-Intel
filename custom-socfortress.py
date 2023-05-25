#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2023, SOCFortress, LLP.
import json
import sys
import time
import os
import ipaddress
import re
from socket import socket, AF_UNIX, SOCK_DGRAM
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)
# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    debug("# API Key")
    debug(apikey)
    debug("# File location")
    debug(alert_file_location)
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
    # Request SOCFortress info
    msg = request_socfortress_api(json_alert,apikey)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file,"a")
        f.write(msg)
        f.close()

def collect_source_1(data):
    comment = data['comment']
    value = data['value']
    timestamp = data['timestamp']
    if timestamp is None:
        timestamp = '1679526769'
    category = data['category']
    type = data['type']
    virustotal_url = data['virustotal_url']
    return comment, value, timestamp, category, type, virustotal_url

def collect_source_2(data):
  comment = data['comment']
  value = data['value']
  type = data['type']
  last_seen = data['last_seen']
  report_id = data['report_id']
  report_url = data['report_url']
  virustotal_url = data['virustotal_url']
  return comment, value, type, last_seen, report_id, report_url, virustotal_url

def collect_source_3(data):
  comment = data['comment']
  value = data['value']
  type = data['type']
  last_seen = data['last_seen']
  virustotal_url = data['virustotal_url']
  return comment, value, type, last_seen, virustotal_url

def is_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        debug(f"{value} is a valid IPv4 address.")
        return True
    except ipaddress.AddressValueError:
        debug(f"{value} is not a valid IPv4 address.")
        return False

def is_domain(value):
    try:
        domain_regex = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", re.IGNORECASE)
        if domain_regex.match(value):
           debug(f"{value} is a valid domain name.")
           return True
        else:
            debug(f"{value} is not a valid domain name.")
            return False
    except Exception as e:
        debug(f"Error: {e}")
        return False

def ioc_source(data, ioc_value):
    result = data['ioc_source']
    if result == '1':
        return True
    return False

def has_report(data, ioc_value):
    if 'report_found' in data:
        return True
    return False

def query_api(ioc_value, apikey):
  params = {'value': ioc_value,}
  headers = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  "x-api-key": apikey,
  "module-version": "1.0",
  }
  response = requests.get('https://intel.socfortress.co/search', params=params, headers=headers)
  if response.status_code == 200:
      json_response = response.json()
      data = json_response.get('data')
      return data
  elif response.status_code == 403 or response.status_code == 429:
      json_response = response.json()
      data = json_response
      alert_output = {}
      alert_output["socfortress"] = {}
      alert_output["integration"] = "custom-socfortress"
      alert_output["socfortress"]["status_code"] = response.status_code
      alert_output["socfortress"]["message"] = json_response['message']
      send_event(alert_output)
      exit(0)
  else:
      alert_output = {}
      alert_output["socfortress"] = {}
      alert_output["integration"] = "custom-socfortress"
      json_response = response.json()
      debug("# Error: The SOCFortress integration encountered an error")
      alert_output["socfortress"]["status_code"] = response.status_code
      alert_output["socfortress"]["message"] = json_response['error']
      send_event(alert_output)
      exit(0)

def request_socfortress_api(alert, apikey):
    alert_output = {}
    # Collect the IoC Type - Currently only Supports SYSMON For Windows
    event_source = alert["rule"]["groups"][0]
    if 'windows' in event_source.lower():
        if 'hashes' in alert["data"]["win"]["eventdata"]:
            ## Regex Pattern used based on SHA256 lenght (64 characters)
            regex_file_hash = re.compile('\w{64}')
            ioc_value = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            data = query_api(ioc_value, apikey)
        elif 'destinationIp' in alert["data"]["win"]["eventdata"]:
            ioc_value = alert["data"]["win"]["eventdata"]["destinationIp"]
            ipv4 = is_ipv4(ioc_value)
            if ipv4 and ipaddress.ip_address(ioc_value).is_global:
                data = query_api(ioc_value, apikey)
            else:
                return(0)
        elif 'queryName' in alert["data"]["win"]["eventdata"]:
            ioc_value = alert["data"]["win"]["eventdata"]["queryName"]
            domain = is_domain(ioc_value)
            if domain:
                data = query_api(ioc_value, apikey)
            else:
                return(0)
        else:
            return(0)
    else:
        return(0)
    # Create alert
    alert_output["socfortress"] = {}
    alert_output["integration"] = "custom-socfortress"
    alert_output["socfortress"]["found"] = 0
    alert_output["socfortress"]["source"] = {}
    alert_output["socfortress"]["source"]["alert_id"] = alert["id"]
    alert_output["socfortress"]["source"]["agent_name"] = alert["agent"]["name"]
    alert_output["socfortress"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["socfortress"]["source"]["description"] = alert["rule"]["description"]
    alert_output["socfortress"]["source"]["processGuid"] = alert["data"]["win"]["eventdata"]["processGuid"]
    alert_output["socfortress"]["source"]["ioc_value"] = ioc_value
    ioc_value = ioc_value
    # Check if SOCFortress has any info about the IoC
    if ioc_source(data, ioc_value):
        alert_output["socfortress"]["ioc_source"] = 1
    else:
        alert_output["socfortress"]["ioc_source"] = 2
        # Check if SOCFortress has any reports about the IoC
        report_found = has_report(data, ioc_value)
        if report_found:
            alert_output["socfortress"]["report_found"] = 1
        else:
            alert_output["socfortress"]["report_found"] = 0
        if alert_output["socfortress"]["ioc_source"] == 2 and alert_output["socfortress"]["report_found"] == 1:
            comment, value, type, last_seen, report_id, report_url, virustotal_url = collect_source_2(data)
            # Populate JSON Output with SOCFortress results
            alert_output["socfortress"]["status_code"] = 200
            alert_output["socfortress"]["comment"] = comment
            alert_output["socfortress"]["value"] = value
            alert_output["socfortress"]["last_seen"] = last_seen
            alert_output["socfortress"]["type"] = type
            alert_output["socfortress"]["report_id"] = report_id
            alert_output["socfortress"]["report_url"] = report_url
            alert_output["socfortress"]["virustotal_url"] = virustotal_url
    
        if alert_output["socfortress"]["ioc_source"] == 2 and alert_output["socfortress"]["report_found"] == 0:
            comment, value, type, last_seen, virustotal_url = collect_source_3(data)
            alert_output["socfortress"]["status_code"] = 200
            alert_output["socfortress"]["comment"] = comment
            alert_output["socfortress"]["value"] = value
            alert_output["socfortress"]["last_seen"] = last_seen
            alert_output["socfortress"]["type"] = type
            alert_output["socfortress"]["virustotal_url"] = virustotal_url

    # Info about the IoC found in SOCFortress
    if alert_output["socfortress"]["ioc_source"] == 1:
        comment, value, timestamp, category, type, virustotal_url = collect_source_1(data)
        # Populate JSON Output object with SOCFortress results
        alert_output["socfortress"]["status_code"] = 200
        alert_output["socfortress"]["comment"] = comment
        alert_output["socfortress"]["value"] = value
        alert_output["socfortress"]["timestamp"] = timestamp
        alert_output["socfortress"]["category"] = category
        alert_output["socfortress"]["type"] = type
        alert_output["socfortress"]["virustotal_url"] = virustotal_url

    debug(alert_output)
    return(alert_output)

def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:socfortress:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->socfortress:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True
        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()
        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)
        # Main function
        main(sys.argv)
    except Exception as e:
        debug(str(e))
        raise
