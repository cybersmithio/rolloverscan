#!/usr/bin/python3
#
# This searches all the recent Tenable.io scans, or for one scan name in particular.
# If the scan or scans has any IP addresses that were missed, because the scan may have run into an exclusion window,
# this script will create a "rollover" scan, which is just a copy of the original scan where the targets are just the IP addresses that were missed.
#
# For this script to run properly, the scans it is examining should be finished.  (i.e. run this script after the start of the exclusion window)
#
# Version 0.9 - Just does tenable.io for now
#
#
# Example usage with environment variables:
# export TIO_ACCESS_KEY="********************"
# export TIO_SECRET_KEY="********************"
# python3 ./rolloverscan.py --scanname "My basic vulnerability scan" --hours 72
#
# Requires the following:
#   pip install pytenable ipaddr netaddr

import json
import os
import csv
import sys
import time
from tenable.io import TenableIO
import argparse
import netaddr
import ipaddr
import re
import time

#Returns an integer of the scan ID
def GetScanID(DEBUG,tio,scanname):
    if DEBUG:
        print("Searching for scan with name: "+str(scanname))
    scanid=False
    for scan in tio.scans.list():
        if DEBUG:
            print("Scan: ",scan)
        if scan['name'] == str(scanname):
            if DEBUG:
                print("Found scan name "+str(scanname)+" with ID "+str(scan['id']))
            scanid=int(scan['id'])
    return(scanid)


#Right now, host and port are ignored
def EvaluateScans(DEBUG,accesskey,secretkey,host,port,scanname,hours):
    #Create the connection to Tenable.io
    tio=TenableIO(accesskey, secretkey)

    if DEBUG:
        print("Scans in the last "+str(hours)+" will be reviewed")


    #If a scan name was provided, then find the scan ID.
    #Otherwise set scan ID as False.
    #If a scan name was provided and it cannot be found, then exit.
    if scanname == "":
        scanid=False
    else:
        scanid=GetScanID(DEBUG,tio,scanname)
        if not scanid:
            print("Could not find scan name:",str(scanname))
            return(False)
        if DEBUG:
            print("Found scan ID:",str(scanid))


    MATCH=False
    #Search through the scans.
    print("Retrieving list of all scans")
    for scan in tio.scans.list():
        if DEBUG:
            print("Scan name:",scan['name'])
            print("Scan ID:",scan['id'])
            print(scan)
        #Are we looking for a particular scan ID?
        if scanid != False:
            #Yes, see if we found that scan ID
            if(int(scan['id']) == scanid):
                if DEBUG:
                    print("Found the scan by ID.")
                evalresults=EvaluateLastScanResult(DEBUG,tio,int(hours),int(scan['id']))
            else:
                evalresults=False
        else:
            #No, we want to look at all scans, so let's look at this one.
            sys.stdout.write(".")
            evalresults=EvaluateLastScanResult(DEBUG,tio,int(hours),int(scan['id']))

        #Make sure we're not creating a rollover scan on a rollover scan. I don't want to get into that for now.
        if str(scan['name']).startswith("ROLLOVER - "):
            evalresults=False

        if evalresults != False:
            MATCH=True
            (folderid,missed)=evalresults
            if DEBUG:
                print("Creating a rollover scan for these IP addresses:",missed)
            CreateRolloverScan(DEBUG,tio,scan['name'],int(scan['id']),folderid,missed)
    print("")
    if not MATCH:
        print("There were no matching scans found that require a rollover scan to be created.")

def CreateRolloverScan(DEBUG,tio,scanname,scanid,folderid,missed):
    rollovername="ROLLOVER - "+str(time.time())+" - "+str(scanname)
    if DEBUG:
        print("Copying scan ID "+str(scanid)+" to scan name "+rollovername)
    try:
        newscan=tio.scans.copy(scanid,folder_id=folderid,name=rollovername)
    except:
        print("Error creating rollover scan for scan ID "+str(scanid)+" in folder ID "+str(folderid)+" with name \""+rollovername+"\"")
        return(False)
    if DEBUG:
        print(newscan)
        print("New scan ID is "+str(newscan['id']))

    tio.scans.configure(newscan['id'],targets=missed)
    print("A rollover scan with the name \""+rollovername+"\" has been created with the following targets:")
    for i in missed:
        print(i)

#Take a scanid and see if the results were within the last hours specified.
#Return False is not in the time range.
#Otherwise look for any missed IP addresses and return a list of those, or False if no missing IP addresses
def EvaluateLastScanResult(DEBUG,tio,hours,scanid):
    if DEBUG:
        print("Gathering scan results from scan ID:",str(scanid))

    try:
        results=tio.scans.results(scanid)
    except:
        print("Error looking up scan with ID "+str(scanid)+".  Was it just deleted while this script was running?")
        return(False)

    if DEBUG:
        print("Scan results:",results)
        try:
            print("\n\nScan notes:",results['notes'])
        except:
            print("\n\nScan notes: None")

    if not 'notes' in results:
        if DEBUG:
            print("There were no notes in this scan, so not going to create a rollover.")
        return(False)

    folderid=0
    if 'info' in results:
        if DEBUG:
            print("Scan start:",results['info']['scan_start']) if 'scan_start' in results['info'] else print("No scan start")
            print("Scan end:",results['info']['scan_end']) if 'scan_end' in results['info'] else print("No scan end")
        try:
            folderid=int(results['info']['folder_id'])
        except:
            folderid=0

        scan_start=int(results['info']['scan_start']) if 'scan_start' in results['info'] else 0

    if scan_start >= time.time()-(hours*3600):
        if DEBUG:
            print("This scan was started in the time range of "+str(hours)+" hours")
    else:
        if DEBUG:
            print("This scan was NOT started in the time range of "+str(hours)+" hours")
        return(False)

    missed=[]
    for msg in results['notes']:
        if DEBUG:
            print("Message in notes:",msg)
        ipaddrs=re.findall("Rejected attempt to scan ([0-9\.:]+), as it violates user-defined rules", msg['message'], flags=re.IGNORECASE)
        for i in ipaddrs:
            if DEBUG:
                print("This IP address was missed: \"" +str(i)+"\"")
            missed.append(str(i))
    if DEBUG:
        print("These IP addresses were missed from the scan:",missed)
        print("Total IPs missing from scan:",len(missed))
    if len(missed) == 0:
        return(False)
    else:
        return(folderid,missed)








    #Look at just the results that returned in the time range specified by hours.
    #Check if there were missing IPs in the notes.
    #For any scans with missing IP addresses, create a copy of the scan with the target of just the missing IP addresses





    return(True)




######################
###
### Program start
###
######################

# Get the arguments from the command line
parser = argparse.ArgumentParser(description="Searches Tenable.io for scans that missed IP addresses and creates rollover scans.")
parser.add_argument('--scanname',help="The name of the scan to evaluate. The default is to look at all scans within the time range (If there are duplicate names then it takes the last matching one)",nargs=1,action="store")
parser.add_argument('--hours',help="How far back to search through scan results.  Scan start time is used as the reference.  The default is 24 hours.",nargs=1,action="store")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store")
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store")
parser.add_argument('--host',help="The Tenable.io host. (Default is cloud.tenable.com)",nargs=1,action="store")
parser.add_argument('--port',help="The Tenable.io port. (Default is 443)",nargs=1,action="store")
parser.add_argument('--debug',help="Turn on debugging",action="store_true")

args=parser.parse_args()

DEBUG=False

if args.debug:
    DEBUG=True
    print("Debugging is enabled.")



# Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('TIO_ACCESS_KEY') is None:
    accesskey = ""
else:
    accesskey = os.getenv('TIO_ACCESS_KEY')

# If there is an access key specified on the command line, this override anything else.
try:
    if args.accesskey[0] != "":
        accesskey = args.accesskey[0]
except:
    nop = 0


if os.getenv('TIO_SECRET_KEY') is None:
    secretkey = ""
else:
    secretkey = os.getenv('TIO_SECRET_KEY')


# If there is an  secret key specified on the command line, this override anything else.
try:
    if args.secretkey[0] != "":
        secretkey = args.secretkey[0]
except:
    nop = 0

try:
    if args.host[0] != "":
        host = args.host[0]
except:
    host = "cloud.tenable.com"

try:
    if args.port[0] != "":
        port = args.port[0]
except:
    port = "443"

try:
    if args.scanname[0] != "":
        scanname=args.scanname[0]
except:
    scanname=""

try:
    if args.hours[0] != "":
        hours=args.hours[0]
except:
    hours=24


print("Connecting to cloud.tenable.com with access key",accesskey,"to report on assets")

EvaluateScans(DEBUG,accesskey,secretkey,host,port,scanname,hours)


