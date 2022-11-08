#!/usr/bin/env python3

import argparse
import os
import json
import time
import sys
from dateutil.parser import parse

# Helper functions

def exec(cmd):
    stream = os.popen(cmd)
    return(stream.read())

def cve_exec(arguments):
    stream = os.popen("cve {} --raw".format(arguments))
    json_data = json.loads(stream.read())
    stream.close()
    return json_data


# Main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update CVE JSON5.0 records', allow_abbrev=False)
    parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")
    #parser.add_argument('--skip', type=str, metavar="test1,test2", default="", help="comma separated list of check to check")
    #parser.add_argument('--list', action="count", default=0, help="list all checks and exit" )
    #parser.add_argument('--min-reserved', type=int, metavar="N", default=0, help="Minimum number of reserved IDs for the current year" )
    #parser.add_argument('--reserve', type=int, metavar="N", default=0, help="Reserve N new entries if reserved for this year is below minimum")
    #parser.add_argument('--schema', type=str, metavar="./cve50.json", default="./cve50.json", help="Path to the CVE json50 schema file")


    args = parser.parse_args()

    # Is CVE lib installed
    cvelib_path=exec("which cve")
    if cvelib_path == "":
        print("No output for `which cve`, cvelib is no installed", file=sys.stderr)
        exit(255)
    org = exec("cve org")
    if "ERROR" in org :
        print("Unable to list organisation via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)
    org = cve_exec("org")
    cves = cve_exec("list")

    updated=0
    for root, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith(".json"):
                # Get basic data
                filename = os.path.join(root,file)
                print(filename)
                cve_id_from_file=os.path.basename(filename).replace(".json","")

                # Sanity checks
                file_valid=True

                # Is JSON valid
                try:
                    f = open(filename)
                    json_data = json.load(f)
                    f.close()
                    cve_id = json_data['cveMetadata']['cveId']
                except:
                    json_data={}
                    print("Unable to read json from file {}, skipping file.".format(filename),file=sys.stderr)
                    cve_id="INVALID"
                    file_valid=False

                # Do the IDs match?
                if file_valid and cve_id_from_file !=  cve_id :
                    print("CVE ID from file {}, does NOT equal CVE ID from file name {}, skipping file.".format(cve_id,cve_id_from_file),file=sys.stderr)
                    file_valid=False

                # Do you own the record?
                if file_valid:
                    cve_metadata=cve_exec("show {}".format(cve_id))
                    if cve_metadata["owning_cna"] != org["short_name"] :
                        print("{} is not owned by {}, but by {}, skipping file.".format(cve_id, org["short_name"],cve_metadata["owning_cna"]),file=sys.stderr)
                        file_valid=False

                # Is the CVE not rejected?
                if cve_metadata["state"] == "REJECTED" :
                    print("{} is 'REJECTED' on the server, skipping.".format(cve_id),file=sys.stderr)
                    file_valid=False

                # Doers the record ened to be published or updated?
                if file_valid and json_data["cveMetadata"]["state"] == "PUBLISHED":
                    file_date_str=exec("git log -1 --pretty='format:%ci' {}".format(filename))
                    file_date = parse(file_date_str)
                    server_date = parse(cve_metadata["time"]["modified"])
                    if ( file_date > server_date or cve_metadata["state"] == "RESERVED" ) :
                        result = cve_exec("publish -j '{}' {}".format(json.dumps(json_data["containers"]["cna"], separators=(',', ':')), cve_id))
                        print(result["message"])
                        updated=updated+1
                    else:
                        print("Record for {} is up to date".format(cve_id))

                if file_valid and json_data["cveMetadata"]["state"] != "RESERVED" and json_data["cveMetadata"]["state"] != "PUBLISHED" :
                    print("State of {} is not 'RESERVED' or 'PUBLISHED', don;t know what to do with a '{}' record. Skipping.".format(cve_id,json_data["cveMetadata"]["state"]))
                print("\n{} record(s) published/updated.".format(updated))
