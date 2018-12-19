# Purpose
Creates a "rollover" scan, which contains any IP addresses that were flagged by Tenable.io as missed.

# Overview
This searches all the recent Tenable.io scans, or for one scan name in particular.
If the scan or scans has any IP addresses that were missed, because the scan may have run into an exclusion window,
this script will create a "rollover" scan, which is just a copy of the original scan where the targets are just the IP addresses that were missed.


For this script to run properly, the scans it is examining should be finished.  (i.e. run this script after the start of the exclusion window)
# Example

This is usage with environment variables:
   export TIO_ACCESS_KEY="********************"
   export TIO_SECRET_KEY="********************"
   python3 ./rolloverscan.py --scanname "My basic vulnerability scan" --hours 72
