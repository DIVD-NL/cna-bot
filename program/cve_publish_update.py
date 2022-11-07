#!/usr/bin/env python3

import argparse
import os
import json
import datetime

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
    #parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")
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
    cves = cve_exec("list")
    if "ERROR" in org :
        print("Unable to list cve entries via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)

    for root, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith(".json"):
                filename = os.path.join(root,file)
                cve_id_from_file=os.path.basename(filename).replace(".json")
                file_valid=True
                try:
                    f = open(filename)
                    json_data = json.load(f)
                    f.close()
                except:
                    json_data={}
                    print("Unable to read json from file {}, skipping file.".format(filename),file=sys.stderr)
                    file_valid=False
                if file_valid && cve_id_from_file != json_data['cveMetadata']['cveId'] :
                    print("CVE ID from file {}, doe NOT equal CVE ID from file name {}, skippinf file.",file=sys.stderr)
                    file_valid=False
                if file_valid:
                    print("Valid")
