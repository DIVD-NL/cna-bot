#!/usr/bin/env python3

import argparse
import os
import re
import json
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
import datetime
import sys

# General checks

def minimum_reserved(args) :
    # Check if we have have the minimum number of CVE IDs reserved
    count = 0
    if args.min_reserved > 0:
        year = datetime.date.today().year
        reserved = cve_exec("list --state reserved --year {}".format(year))
        if len(reserved) < args.min_reserved:
            if args.reserve > 0:
                count = args.min_reserved - len(reserved)
                if count < args.reserve :
                    count = args.reserve
                json_txt=cve_exec("reserve {}".format(count))
                cves = cve_exec("list")
            else:
                return("For {}, you have {} reserved entries, this is less then the minimum number of {}".format(year, len(reserved),args.min_reserved))
    reserved = cve_exec("list --state reserved")
    ids = ""
    if count > 0 :
        ids = ids + "Allocated {} new CVE IDs\n".format(count)
    if len(reserved) > 0:
        ids = ids + "Reserved CVE IDs:\n"
        for cve in sorted(reserved, key=lambda x: x["cve_id"]):
            ids=ids+cve["cve_id"]+"\n"
    return True, ids

def published_in_repo(args):
    results = []
    remote = {}
    for cve in cves:
        filename = cve["cve_id"]+".json"
        found = False
        if cve["state"] == "PUBLISHED":
            for root, dirs, files in os.walk(args.path):
                if filename in files:
                    found = True
                    break
            if not found:
                results.append("No json file found for {}".format(cve["cve_id"]))
    if len(results) > 0:
        return False, "\n".join(results)
    else:
        return True, None

# File based checks

def file_valid_json1(file,json_data,args) :
    # Check if the JSON is valid ad accoording to spec
    results = []

    try:
        f = open(file)
        my_json_data = json.load(f)
        f.close
    except ValueError as err:
        results.append("Error loading JSON: {}".format(err))

    if len(results) == 0 :
        v = Draft202012Validator(json50schema)
        for validationError in sorted(v.iter_errors(json_data), key=str):
            results.append("Schema validation of CVE record failed. The reason is likely one or more of those listed below:")
            for suberror in sorted(validationError.context, key=lambda e: e.schema_path):
                path = list(suberror.schema_path)
                results.append("{}\n{}".format(suberror.message," / ".join(str(x) for x in path)))

    # return results
    if len(results) == 0:
        return True, None
    else:
        return False, "\n".join(results)


def file_name(file,json_data,args) :
    # Check if the file name is OK
    results = []
    basename = os.path.basename(file)

    # Test name
    if not re.match("^CVE\\-(199|2\\d\\d)\\d\\-\\d{4,}\\.json$",basename) :
        results.append("Filename doesn't match the pattern \"CVE-\\d{4}\\-\\d{4,}\\.json")

    # Test ID
    try:
        cve_from_name = basename.replace(".json","")
        cve_from_file = json_data["cveMetadata"]["cveId"]
        if cve_from_name != cve_from_file :
            results.append("CVE ID from filename ({}), doesn't match CVE ID from json ({})".format(cve_from_name, cve_from_file))
    except:
        results.append("Unable to determine CVE ID from json")

    # return results
    if len(results) == 0:
        return True, None
    else:
        return False, "\n".join(results)

def has_record(file,json_data,args) :
    cve_id = os.path.basename(file).replace(".json","")
    for cve in cves:
        if cve["cve_id"] == cve_id:
            return True, None
    return False, "You have not published or reserved {}".format(cve_id)

def state_match(file,json_data,args) :
    if "cveMetadata" in json_data :
        cve_id = json_data["cveMetadata"]["cveId"]
        metadata = { "state" : "Not ours" }
        for cve in cves :
            if cve["cve_id"] == cve_id :
                metadata = cve
                break
        if metadata["state"] == json_data["cveMetadata"]["state"] :
            # Ok
            return True, None
        if json_data["cveMetadata"]["state"] == "REJECTED"  :
            return False, "State mismatch: local is 'REJECTED' but remote is '{}'".format(metadata["state"])
        if json_data["cveMetadata"]["state"] == "PUBLISHED" and metadata["state"] == "REJECTED" :
            return False, "State mismatch: local is 'REJECTED' but remote is '{}'".format(metadata["state"])
        if json_data["cveMetadata"]["state"] == "RESERVED" :
            return False, "State mismatch: local is 'REJECTED' but remote is '{}'".format(metadata["state"])
        return True, None
    else:
        return False, "JSON invalid"

def publisher_match(file,json_data,args) :
    cve_id = json_data["cveMetadata"]["cveId"]
    metadata = cve_exec("show {}".format(cve_id))
    if metadata["owning_cna"] != org["short_name"] :
        return False, "Owner mismatch: remote is owned by '{}' but we are '{}'".format(metadata["owning_cna"],org["short_name"])
    return True, None

# Checks object and global variables

checks = {
    "min_reserved"      : { "type": "gen",  "func": minimum_reserved,  "description" : "Check if we have am minimum number of reserved entries" },
    "published_in_path" : { "type": "gen",  "func": published_in_repo, "description" : "Check if all published CVE records are in the path"},
    "json_valid"        : { "type": "file", "func": file_valid_json1,  "description" : "Check if the file name/location is valid" },
    "filename"          : { "type": "file", "func": file_name,         "description" : "Check if a file is valid JSON" },
    "has_record"        : { "type": "file", "func": has_record,        "description" : "Check if a CVE ID is reserved or published for this CVE record" },
    "state_match"       : { "type": "file", "func": state_match,       "description" : "Check if local and remote CVE record is consistent" },
    "publisher_match"   : { "type": "file", "func": has_record,        "description" : "Check if CVE record is owned by us" },
}

cves = []

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
    parser = argparse.ArgumentParser(description='Check CVE JSON5.0 records', allow_abbrev=False)
    parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")
    parser.add_argument('--skip', type=str, metavar="test1,test2", default="", help="comma separated list of check to check")
    parser.add_argument('--list', action="count", default=0, help="list all checks and exit" )
    parser.add_argument('--min-reserved', type=int, metavar="N", default=0, help="Minimum number of reserved IDs for the current year" )
    parser.add_argument('--reserve', type=int, metavar="N", default=0, help="Reserve N new entries if reserved for this year is below minimum")
    parser.add_argument('--schema', type=str, metavar="./cve50.json", default="./cve50.json", help="Path to the CVE json50 schema file")


    args = parser.parse_args()

    if args.list > 0 :
        print("The following checks are available:")
        for id in checks:
            print("{:15s} - {}".format(id,checks[id]["description"]))
        exit(0)

    skips=args.skip.split(",")

    if os.path.exists(args.schema) :
        f = open(args.schema)
        json50schema = json.load(f)
        f.close()
    else:
        print("Schema file does not exist",file=sys.stderr)
        exit(255)

    # Is CVE lib installed
    cvelib_path=exec("which cve")
    if cvelib_path == "":
        print("No output for `which cve`, cvelib is no installed", file=sys.stderr)
        exit(255)
    org = exec("cve org")
    if "ERROR" in org :
        print("Unable to list organisation via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)
    cves = cve_exec("list")

    check_pass = True
    for id in checks:
        if id not in skips and checks[id]["type"] != "file":
            print("{:15s}...".format(id),end='')
            passed, result = checks[id]["func"](args)
            if passed :
                print("PASS")
                if(result):
                    print(result)
            else:
                print("FAIL\n{}".format(result))
                check_pass = False
            print()
    for root, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith(".json"):
                filename = os.path.join(root,file)
                print("File: {}".format(filename))
                try:
                    f = open(filename)
                    json_data = json.load(f)
                    f.close()
                except:
                    json_data={}
                for id in checks:
                    if id not in skips and checks[id]["type"] == "file":
                        print("{:15s}...".format(id),end='')
                        passed, result = checks[id]["func"](filename,json_data,args)
                        if passed :
                            print("PASS")
                            if(result):
                                print(result)
                        else:
                            check_pass = False
                            print("FAIL\n{}".format(result))
                print()
    if check_pass == True:
        exit(0)
    else:
        exit(1)
