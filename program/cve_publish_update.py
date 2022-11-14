#!/usr/bin/env python3

import argparse
import os
import json
import time
import sys
from deepdiff import DeepDiff
from dateutil.parser import parse
from cvelib.cve_api import CveApi

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

# Global

cve_api = None

# Main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update CVE JSON5.0 records', allow_abbrev=False)
    parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")

    args = parser.parse_args()

    cve_api = cve_api_login()
    try:
        org = cve_api.show_org()
    except:
        print("Unable to list organisation via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)

    updated=0
    created=0
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
                    cve_metadata = cve_api.show_cve_id(cve_id)
                    if cve_metadata["owning_cna"] != org["short_name"] :
                        print("{} is not owned by {}, but by {}, skipping file.".format(cve_id, org["short_name"],cve_metadata["owning_cna"]),file=sys.stderr)
                        file_valid=False

                # Is the CVE not rejected?
                if cve_metadata["state"] == "REJECTED" :
                    print("{} is 'REJECTED' on the server, skipping.".format(cve_id),file=sys.stderr)
                    file_valid=False

                # Doers the record ened to be published or updated?
                if file_valid and cve_metadata["state"] == "RESERVED" and json_data["cveMetadata"]["state"] == "PUBLISHED":
                    # Need to publish this CVE
                    try:
                        result = cve_api.publish(cve_id,json_data["containers"]["cna"])
                    except Exception as e:
                        print(e)
                    else:
                        print(result["message"])
                        created=createded+1


                if file_valid and cve_metadata["state"] == "PUBLISHED" and json_data["cveMetadata"]["state"] == "PUBLISHED":
                    # We need to update the record if the local record is newer then the server record and the records are different
                    file_date_str=exec("git log -1 --pretty='format:%ci' {}".format(filename))
                    file_date = parse(file_date_str)
                    server_date = parse(cve_metadata["time"]["modified"])
                    if ( file_date > server_date or cve_metadata["state"] == "RESERVED" ) :
                        cve_record = cve_api.show_cve_record(cve_id)
                        diff = DeepDiff(
                            cve_record,
                            json_data,
                            exclude_paths= [
                                "root['containers']['cna']['providerMetadata']['dateUpdated']",
                                "root['cveMetadata']"
                            ]
                        )
                        if diff != {}:
                            try:
                                result = cve_api.update_published(cve_id,json_data["containers"]["cna"])
                            except Exception as e:
                                print(e)
                            else:
                                print(result["message"])
                                updated=updated+1
                        else:

                            print("Record for {} is up to date".format(cve_id))
                    else:
                        print("Record for {} is up to date".format(cve_id))

                if file_valid and json_data["cveMetadata"]["state"] != "RESERVED" and json_data["cveMetadata"]["state"] != "PUBLISHED" :
                    print("State of {} is not 'RESERVED' or 'PUBLISHED', don't know what to do with a '{}' record. Skipping.".format(cve_id,json_data["cveMetadata"]["state"]))
    print("\n{} record(s) created, {} record(s) updated.".format(created,updated))
