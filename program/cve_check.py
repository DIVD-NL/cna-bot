#!/usr/bin/env python3

import argparse
import os
import re
import json
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
import datetime
import sys
from cvelib.cve_api import CveApi

# General checks

def minimum_reserved(args) :
    global cves
    # Check if we have have the minimum number of CVE IDs reserved
    count = 0

    if args.min_reserved > 0:
        year = datetime.date.today().year
        num_reserved = 0
        reserved = []
        for cve in cves:
            if cve["state"] == "RESERVED" and cve["cve_year"] == str(year) :
                reserved.append(cve)
        if len(reserved) < args.min_reserved:
            if args.reserve > 0:
                count = args.min_reserved - len(reserved)
                if count < args.reserve :
                    count = args.reserve
                json_txt=cve_api.reserve(count, False, year)
                cves = cve_api.list_cves()
            else:
                return False, "For {}, you have {} reserved entries, this is less then the minimum number of {}".format(year, len(reserved),args.min_reserved)
    reserved = []
    for cve in cves:
        if cve["state"] == "RESERVED" :
            reserved.append(cve)
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
    for cve in sorted(cves, key=lambda x: x["cve_id"]):
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

def reserved_in_repo(args):
    if args.include_reservations :
        results = []
        remote = {}
        for cve in sorted(cves, key=lambda x: x["cve_id"]):
            filename = cve["cve_id"]+".json"
            found = False
            if cve["state"] == "RESERVED":
                for root, dirs, files in os.walk(args.path):
                    if filename in files:
                        found = True
                        break
                if not found :
                    for root, dirs, files in os.walk(args.reservations_path):
                        if filename in files:
                            found = True
                            break
                if not found:
                    results.append(
                        "No json file found for {}, use `cve show {} --raw > {}/{}.json` to add it".format(
                            cve["cve_id"],cve["cve_id"],args.reservations_path, cve["cve_id"])
                        )
        if len(results) > 0:
            return False, "\n".join(results)
        else:
            return True, None
    else:
        return True, "N/A"


# File based checks

def file_valid_json1(file,json_data,args,type) :
    # Check if the JSON is valid ad accoording to spec
    results = []

    try:
        f = open(file)
        my_json_data = json.load(f)
        f.close
    except ValueError as err:
        results.append("Error loading JSON: {}".format(err))

    if len(results) == 0 and type == "cve":
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


def file_name(file,json_data,args,type) :
    # Check if the file name is OK
    results = []
    basename = os.path.basename(file)

    # Test name
    if not re.match("^CVE\\-(199|2\\d\\d)\\d\\-\\d{4,}\\.json$",basename) :
        results.append("Filename doesn't match the pattern \"CVE-\\d{4}\\-\\d{4,}\\.json")

    # Test ID
    try:
        cve_from_name = basename.replace(".json","")
        if type == "cve" :
            cve_from_file = json_data["cveMetadata"]["cveId"]
        else:
            cve_from_file = json_data["cve_id"]
        if cve_from_name != cve_from_file :
            results.append("CVE ID from filename ({}), doesn't match CVE ID from json ({})".format(cve_from_name, cve_from_file))
    except:
        results.append("Unable to determine CVE ID from json")

    # return results
    if len(results) == 0:
        return True, None
    else:
        return False, "\n".join(results)

def has_record(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    for cve in cves:
        if cve["cve_id"] == cve_id:
            return True, None
    return False, "You have not published or reserved {}".format(cve_id)

def state_match(file,json_data,args,type) :
    if type == "cve" :
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
    else :
        if "cve_id" in json_data :
            cve_id = json_data["cve_id"]
            metadata = { "state" : "Not ours" }
            for cve in cves :
                if cve["cve_id"] == cve_id :
                    metadata = cve
                    break
            if metadata["state"] == "RESERVED" :
                # Ok
                return True, None
            if metadata["state"] == "REJECTED" :
                # Ok
                return True, None
            else :
                return False, "This file is a reservation, but actual state is {}".format(metadata["state"])
        else:
            return False, "JSON invalid"

def publisher_match(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    metadata = cve_api.show_cve_id(cve_id)
    if metadata :
        if metadata["owning_cna"] != org["short_name"] :
            return False, "Owner mismatch: remote is owned by '{}' but we are '{}'".format(metadata["owning_cna"],org["short_name"])
        return True, None
    else :
        return False, "We don't own {}".format(cve_id)

def duplicate_check(file,json_data,args,type) :
    global cve2file
    cve_id = os.path.basename(file).replace(".json","")
    if cve_id in cve2file :
        return False, "There when checking {} we found that file {} also exists for {}".format(file, cve2file[cve_id], cve_id)
    else:
        cve2file[cve_id] = file
    return True, None

def has_refs(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    if "references" in json_data["containers"]["cna"] and len(json_data["containers"]["cna"]["references"]) > 0 :
        return True, None
    else :
        return False, "No references found, at least one reference is required."

def refs_url(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    if "references" in json_data["containers"]["cna"] and len(json_data["containers"]["cna"]["references"]) > 0 :
        invalid = []
        for ref in json_data["containers"]["cna"]["references"] :
            if not re.match(r"^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$", ref["url"]) :
                invalid.append(ref["url"])
        if len(invalid) > 0 :
            return False, "The following references are not valid URLs:\n* \"{}\"".format("\"\n* \"".join(invalid))
        else:
            return True, None
    else :
        return False, "No references found, at least one reference is required."

def refs_tagged(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    if "references" in json_data["containers"]["cna"] and len(json_data["containers"]["cna"]["references"]) > 0 :
        invalid = []
        for ref in json_data["containers"]["cna"]["references"] :
            if "tags" in ref and len(ref["tags"]) > 0 :
                for tag in ref["tags"]:
                    if not tag:
                        invalid.append(ref["url"])
            else :
                invalid.append(ref["url"])
        if len(invalid) > 0 :
            return False, "The following references are not tagged or tagged with an empty tag:\n* \"{}\"".format("\"\n* \"".join(invalid))
        else:
            return True, None
    else :
        return False, "No references found, at least one reference is required."

def vendor_advisory(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    if "references" in json_data["containers"]["cna"] and len(json_data["containers"]["cna"]["references"]) > 0 :
        found = False
        for ref in json_data["containers"]["cna"]["references"] :
            if "tags" in ref and len(ref["tags"]) > 0 :
                for tag in ref["tags"]:
                    if tag == "vendor-advisory":
                        found = True
        if not found :
            return False, "None of the references are tagged as a 'vendor-advisory'"
        else:
            return True, None
    else :
        return False, "No references found, at least one reference is required."

def advisory(file,json_data,args,type) :
    cve_id = os.path.basename(file).replace(".json","")
    if "references" in json_data["containers"]["cna"] and len(json_data["containers"]["cna"]["references"]) > 0 :
        found = False
        for ref in json_data["containers"]["cna"]["references"] :
            if "tags" in ref and len(ref["tags"]) > 0 :
                for tag in ref["tags"]:
                    if tag == "vendor-advisory" or "third-party-advisory":
                        found = True
        if not found :
            return False, "None of the references are tagged as a 'vendor-advisory' or 'third-party-advisory'"
        else:
            return True, None
    else :
        return False, "No references found, at least one reference is required."



# Checks object and global variables
# Supported types are:
# gen  - generic check, not a per file check
# file - check that applies to any json file
# cve  - check that applies to a cve record file (not in reservations_path)
# res  - check that applies to a reservation record (in reservations_path)

checks = {
    "min_reserved"    : { "type": "gen",  "func": minimum_reserved,  "description" : "Is a minimum number of entries reserved?" },
    "publ_in_path"    : { "type": "gen",  "func": published_in_repo, "description" : "Are all published CVE records  in the path?"},
    "reserve_in_path" : { "type": "gen",  "func": reserved_in_repo,  "description" : "Are all reserved CVE ID in the (reserved) path?"},
    "json_valid"      : { "type": "file", "func": file_valid_json1,  "description" : "Is the file name/location valid?" },
    "filename"        : { "type": "file", "func": file_name,         "description" : "Is the  file valid JSON?" },
    "has_record"      : { "type": "file", "func": has_record,        "description" : "Is the CVE ID reserved or published?" },
    "state_match"     : { "type": "file", "func": state_match,       "description" : "Are the local and remote states consistent?" },
    "publisher_match" : { "type": "file", "func": publisher_match,   "description" : "Is the CVE record owned by us?" },
    "duplicate"       : { "type": "file", "func": duplicate_check,   "description" : "Is there only one file for each CVE ID?" },
    "has_refs"        : { "type": "cve",  "func": has_refs,          "description" : "Does the record have references?" },
    "refs_url"        : { "type": "cve",  "func": refs_url,          "description" : "Are references valid urls?" },
    "refs_tagged"     : { "type": "cve",  "func": refs_tagged,       "description" : "Are all references tagged?" },
    "vendor-advisory" : { "type": "cve",  "func": vendor_advisory,   "description" : "Is a reference tagged as vendor-advisory?" },
    "advisory"        : { "type": "cve",  "func": advisory,          "description" : "Is a reference tagged as vendor-advisory or third-party-advisory?" },
}

cves = []
cve2file = {}

# Helper functions

def exec(cmd):
    stream = os.popen(cmd)
    return(stream.read())

def cve_api_login() -> CveApi:
    cve_api = CveApi(
        username=os.getenv("CVE_USER"),
        org=os.getenv("CVE_ORG"),
        api_key=os.getenv("CVE_API_KEY"),
        env=os.getenv("CVE_ENVIRONMENT")
    )
    return cve_api

def log(result, file, logfile) :
    if logfile :
        with open(logfile, "a") as lfh:
            if file :
                lfh.write("In file {} :\n".format(file))
            lfh.write("{}\n".format(result))

# Main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check CVE JSON5.0 records', allow_abbrev=False)
    parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")
    parser.add_argument('--skip', type=str, metavar="test1,test2", default="", help="comma separated list of check to check")
    parser.add_argument('--list', action="count", default=0, help="list all checks and exit" )
    parser.add_argument('--min-reserved', type=int, metavar="N", default=0, help="Minimum number of reserved IDs for the current year" )
    parser.add_argument('--reserve', type=int, metavar="N", default=0, help="Reserve N new entries if reserved for this year is below minimum")
    parser.add_argument('--schema', type=str, metavar="./cve50.json", default="./cve50.json", help="Path to the CVE json50 schema file")
    parser.add_argument('--include-reservations', action="store_true", default=False, help="Include reservations in our records")
    parser.add_argument('--reservations-path', type=str, metavar="./reservations", default="", help="path of directory for reservations")
    parser.add_argument('--log', type=str, metavar="/tmp/cve_check.log", default="", help="Log errors to this file")

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

    if not os.path.exists(args.path) :
        print("Path '{}' does not exist".format(args.path),file=sys.stderr)
        exit(255)

    if args.reservations_path == "" :
        args.reservations_path = "{}/reservations".format(args.path)
    if args.include_reservations:
        if not os.path.exists(args.reservations_path) :
            print("Reservations path '{}' does not exist".format(args.reservations_path),file=sys.stderr)
            exit(255)

    # Is CVE lib installed
    cve_api = cve_api_login()
    try:
        org = cve_api.show_org()
    except:
        print("Unable to list organisation via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)
    cves = list(cve_api.list_cves())

    check_pass = True
    for id in checks:
        if checks[id]["type"] == "gen":
            print("{:15s}...".format(id),end='')
            if id not in skips :
                passed, result = checks[id]["func"](args)
                if passed :
                    print("PASS")
                    if(result):
                        print(result)
                else:
                    print("FAIL\n{}".format(result))
                    log(result,None,args.log)
                    check_pass = False
            else:
                print("SKIP")
    print()
    # CVE record checks
    for root, dirs, files in sorted(os.walk(args.path)):
        # Walk all CVE records, execlude reservations
        for file in sorted(files):
            if file.endswith(".json"):
                filename = os.path.join(root,file)
                if not filename.startswith(args.reservations_path) :
                    print("File: {}".format(filename))
                    try:
                        f = open(filename)
                        json_data = json.load(f)
                        f.close()
                    except:
                        json_data={}
                    for id in checks:
                        if ( checks[id]["type"] == "file" or checks[id]["type"] == "cve" ) :
                            print("{:15s}...".format(id),end='')
                            if id not in skips :
                                passed, result = checks[id]["func"](filename,json_data,args,"cve")
                                if passed :
                                    print("PASS")
                                    if(result):
                                        print(result)
                                else:
                                    check_pass = False
                                    log(result,filename,args.log)
                                    print("FAIL\n{}".format(result))
                            else:
                                print("SKIP")
                    print()
    # Reservation checks
    for root, dirs, files in sorted(os.walk(args.reservations_path)):
        for file in sorted(files):
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
                    if ( checks[id]["type"] == "file" or checks[id]["type"] == "res" ) :
                        print("{:15s}...".format(id),end='')
                        if id not in skips :
                            passed, result = checks[id]["func"](filename,json_data,args,"res")
                            if passed :
                                print("PASS")
                                if(result):
                                    print(result)
                            else:
                                check_pass = False
                                print("FAIL\n{}".format(result))
                                log(result,filename,args.log)
                        else:
                            print("SKIP")
                print()
    if check_pass == True:
        exit(0)
    else:
        exit(1)
