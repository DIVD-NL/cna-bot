# CVE RSUS validate and submit

This GitHub action validates CVE JSON 5.0 format records and (optionally) submits them to the CVE RSUS service.

## Inputs

## `cve-user`

**Required** CVE services user name (usually the email address)

## `cve-org`

**Required** CVE services organisation


## `cve-api-key`

**Required** CVE services api key (Please store this in a GitHub secret)

## `cve-environment`

**Required** CVE services environment (defaults to test)

## `publish`

Set to `true` to publish the records to the CVE services (defaults to false)

## `path`

Path to find CVE records in. Any \*.json file in this riectory is considered a CVE record (defaults to `.`)

## `ignore`

Comma separted list of checks to ignore.

## `min-reserved`

Minimum number of reserved records for the current year.

Action will fail if the number of records in RESERVED state drops below this amount. If `reserve` is set to a number above 0 this action will reserve this many new records.

## `reserve`

Minimum number of records to reserve in one go (0=do not make reservations)

## Example usage

**Soon**

uses: actions/hello-world-docker-action@v2
with:
  who-to-greet: 'Mona the Octocat'
