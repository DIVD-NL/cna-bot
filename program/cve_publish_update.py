#!/usr/bin/env python3

import argparse
import os
import json
import time
import sys
import re
from deepdiff import DeepDiff
from dateutil.parser import parse
from cvelib.cve_api import CveApi
from dateutil.relativedelta import relativedelta
from datetime import datetime

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

def write_json_file(filename, json_data) :
    with open(filename, "w") as f:
        f.write(json.dumps(json_data, indent=2, sort_keys=True))
        f.close()


# Global

cve_api = None

# Main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update CVE JSON5.0 records', allow_abbrev=False)
    parser.add_argument('--path', type=str, metavar=".", default=".", help="path of directory to check")
    parser.add_argument('--update-local', action="store_true", default=False, help="Update local records if they differ from remote records (e.g. in metadata)")
    parser.add_argument('--include-reservations', action="store_true", default=False, help="Include reservations")
    parser.add_argument('--reservations-path', type=str, metavar=".", default="", help="path of directory to check")
    parser.add_argument('--expire-after', type=str, metavar="3M", default="", help="Expire reservations time much after the year has expired via a pull-request, date can be specified as w.g. 30d, 3w, 2m or 1y (default: don't expire)")

    args = parser.parse_args()

    if not os.path.exists(args.path) :
        print("Path '{}' does not exist".format(args.path),file=sys.stderr)
        exit(255)

    if args.reservations_path == "" :
        args.reservations_path = "{}/reservations".format(args.path)
    if args.include_reservations:
        if not os.path.exists(args.reservations_path) :
            print("Reservations path '{}' does not exist".format(args.reservations_path),file=sys.stderr)
            exit(255)

    expire_year=None
    if args.expire_after :
        result = re.search(r"^(\d+)(d|w|m|y)$", args.expire_after)
        if result :
            past_date = datetime.today()
            match result.group(2) :
                case "d" :
                    past_date = datetime.today() - relativedelta(days=int(result.group(1)))
                case "w" :
                    past_date = datetime.today() - relativedelta(weeks=int(result.group(1)))
                case "m" :
                    past_date = datetime.today() - relativedelta(months=int(result.group(1)))
                case "y" :
                    past_date = datetime.today() - relativedelta(years=int(result.group(1)))
            expire_year = past_date.year - 1
        else :
            print("--expire-after is set to '{}', but is should be a number and a period specifier\nE.g. 1d = 1 day, 2w = 2 weeks, 3m = 3 months or 4y = 4 years".format(args.expire_after),file=sys.stderr)
            exit(255)


    cve_api = cve_api_login()
    try:
        org = cve_api.show_org()
    except:
        print("Unable to list organisation via cvelib, have you set your authentication variables?", file=sys.stderr)
        exit(255)

    updated=0
    created=0
    # CVE records
    print("CVE records\n")
    for root, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith(".json") :
                # Get basic data
                filename = os.path.join(root,file)
                if not filename.startswith(args.reservations_path) :
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

                    # Does the record need to be published or updated?
                    if file_valid and cve_metadata["state"] == "RESERVED" and json_data["cveMetadata"]["state"] == "PUBLISHED":
                        # Need to publish this CVE
                        try:
                            result = cve_api.publish(cve_id,json_data["containers"]["cna"])
                        except Exception as e:
                            print(e)
                        else:
                            print(result["message"])
                            created=created+1


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
                                    "root['containers']['cna']['providerMetadata']",
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
                                print("Record for {} is up to date.".format(cve_id))
                        else:
                            print("Record for {} is up to date.".format(cve_id))
                        if file_valid and args.update_local :
                            cve_record = cve_api.show_cve_record(cve_id)
                            diff = DeepDiff(
                                cve_record,
                                json_data
                            )
                            if diff != {} :
                                write_json_file(filename, cve_record)
                                print("Updated local records of {} with remote (meta-)data.".format(cve_id))

                    if file_valid and json_data["cveMetadata"]["state"] != "RESERVED" and json_data["cveMetadata"]["state"] != "PUBLISHED" :
                        print("State of {} is not 'RESERVED' or 'PUBLISHED', don't know what to do with a '{}' record. Skipping.".format(cve_id,json_data["cveMetadata"]["state"]))

    print("\nReservations\n")
    if args.include_reservations:
        # Reservations
        cves = list(cve_api.list_cves())
        reserved = {}
        for cve in cves :
            if cve["state"] == "RESERVED" or cve["state"] == "REJECTED" :
                reserved[cve["cve_id"]] = cve

        # We did not expire CVE IDs, yet.
        expired = 0

        # reservations.lock files
        locked = []
        for root, dirs, files in os.walk(args.reservations_path):
            for file in files:
                if file== "reservations.lock" :
                    filename = os.path.join(root,file)
                    with open(filename) as lf:
                        for line in lf.readlines() :
                            result = re.search(r"^\s*(CVE\-\d{4}\-\d{4,})?\s*(\#.*)?$", line)
                            if result :
                                if result.group(1):
                                    locked.append(result.group(1))
                            else:
                                print("Incorrect line in {} ignored:\n{}".format(filename, line))

        # First local files
        for root, dirs, files in os.walk(args.reservations_path):
            for file in files:
                if file.endswith(".json") :
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
                        cve_id = json_data['cve_id']
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
                        cve_metadata = reserved[cve_id]
                        if cve_metadata["owning_cna"] != org["short_name"] :
                            print("{} is not owned by {}, but by {}, skipping file.".format(cve_id, org["short_name"],cve_metadata["owning_cna"]),file=sys.stderr)
                            file_valid=False

                    # Do we need to cancel the reservation?
                    if file_valid and json_data['state'] == "REJECTED" and cve_metadata["state"] == "RESERVED" :
                        cve_api.move_to_rejected(cve_id)
                        print("Moved {} to REJECTED state".format(cve_id))
                        reserved[cve_id]["state"] = "REJECTED"
                        updated=updated+1

                    if file_valid and args.update_local :
                        diff = DeepDiff(
                            reserved[cve_id],
                            json_data
                        )
                        if diff :
                            write_json_file(filename, reserved[cve_id])
                            print("Local record for {} updated.".format(cve_id))
                        else :
                            print("Record for {} is up to date.".format(cve_id))

                    # Do we need to expire local reservations?
                    if file_valid and args.expire_after and reserved[cve_id]["state"] != "REJECTED" and cve_id not in locked:
                        result = re.search(r"^CVE\-(\d{4})\-", cve_id)
                        if int(result.group(1)) <= expire_year :
                            reserved[cve_id]["state"] = "REJECTED"
                            write_json_file(filename, reserved[cve_id])
                            print("Local reservation for {} updated to expire reservation.".format(cve_id))
                            expired = expired + 1

                    if file_valid:
                        del reserved[cve_id]

        # Write reservations we don't have locally
        for cve_id in sorted(reserved):
            if cve_id != "INVALID" :
                print("Reservation file for {} does not exist".format(cve_id))
                write_json_file("{}/{}.json".format(args.reservations_path,cve_id),reserved[cve_id])
                print("Created {}/{}.json".format(args.reservations_path,cve_id))

    print("\n{} record(s) created, {} record(s) updated.".format(created,updated))

    if expired > 0 :
        print("{} local reservation(s) updated because they expired, add these CVE IDs to an expired.lock file to preserve them.".format(expired))

