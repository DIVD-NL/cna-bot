# CNA Bot

This GitHub action validates CVE JSON 5.0 format records and (optionally) submits them to the CVE RSUS service.

## Inputs

### `cve-user`

**Required** CVE services user name (usually the email address)

### `cve-org`

**Required** CVE services organisation

### `cve-api-key`

**Required** CVE services api key (Please store this in a GitHub secret)

### `cve-environment`

**Required** CVE services environment (defaults to test)

### `publish`

Set to `true` to publish the records to the CVE services (defaults to false)

### `path`

Path to find CVE records in. Any \*.json file in this directory is considered a CVE record (defaults to `.`)

## `reservations-path`

Path to find CVE ID reservations in. Any \*.json file in this directory is considered a CVE ID reservation (defaults to `<path>/reservations`)

### `ignore`

Comma separted list of checks to ignore.

### `min-reserved`

Minimum number of reserved records for the current year.

Action will fail if the number of records in RESERVED state drops below this amount. If `reserve` is set to a number above 0 this action will reserve this many new records.

### `reserve`

Minimum number of records to reserve in one go (0=do not make reservations)

### `pr`

Create a pull request to bring local records in line with remote records (defaults to `false`)

### `github-token`

A github token to be used by this action. Default ` `. Recommended value: ${{ secrets.GITHUB_TOKEN }}

If you want github actions to run on pull requests created by this action you will have to use a personal Github Access token with at least the `repo`, `org:read` and `discussion:read` scopes.

### `expire-after`

Create pull request (if `pr` is set to `true`) to expire reservations this much time after the end of the year.
Example values are:
* `4d` for 4 days, reservations will expire on or after 5 Jan
* `3w` for 4 weeks, reservations will expire on or after 15 Jan
* `2m` for 2 months, reservations will expire on or after 1 Mar
* `1y` for 1 year, reserveration will expire on or after 1 Jan for reservations before the previous year

### `verbose`

Set to true to increase the output levels. (Defaults to `false`)

### `quiet`

Set to true to output only the minimul output. (Defaults to `false`)
If both `verbose` and `quiet` are set, `quiet` wins

## Versions

For the stable version use `DIVD-NL/cna-bot@v1` (recommended)

For the current beta version use `DIVD-NL/cna-bot@v1.4`

## Example usage

See: https://github.com/DIVD-NL/cna-admin-test

In this repo the CVE records are in `./records` and it has this workflow configuration

```
# test_and_update_cve_records.yml
on:
  push:
    branches:
      - 'main'
  pull_request:
    branches:
      - 'main'
  schedule:
    - cron: "5 4 * * *"


jobs:
  test_and_update_cve_records:
    runs-on: ubuntu-latest
    steps:
      # Get the repository's code
      - name: Checkout
        uses: actions/checkout@v3
      # Check CVE records and publish them    
      - name: CVE RSUS check and upload
        uses: DIVD-NL/cna-bot@v1
        with: 
          cve-user        : ${{ secrets.CVE_USER }}
          cve-org         : ${{ secrets.CVE_ORG }}
          cve-api-key     : ${{ secrets.CVE_API_KEY }}
          cve-environment : test                                        # Change to prod for actual use
          publish         : ${{ github.ref == 'refs/heads/main' }}      # Only publish when we merge into the main branch
          path            : records                                     # This is where the CVE records live
          path            : records/reservations                        # This is where reservation CVE IDs live
          ignore          : ""                                          # Don't ignore any checks
          min-reserved    : 10                                          # Keep at least 10 reserved records (for the current year)
          reserve         : 10                                          # Reserve a minimum of 10 records at a time 
          pr              : ${{ github.event_name != 'pull_request' }}  # Create a PR when we push or run on schedule
          github-token    : ${{ secrets.GITHUB_TOKEN }}          
          expire-after    : "1y"

```

## reservations.lock

You can create a this file to exclude CVE ID reservations from automatic expiry. You can create one or more of these files anywhere in the `reservations-path`. You must include one CVE ID per line and `#` style comments are allowed.

You can also use this file for some local administration.

E.g.
```
# reservations.lock

# DIVD-2010-00001
# Owner: Frank
CVE-2010-66666  # Ticket: 1245
CVE-2010-66667  # Ticket: 1246

# DIVD-2010-00002
CVE-2010-66668  # Ticket: 1249
CVE-2010-66669  # Ticket: 1250
```

## Detailed explanation
I will explain each part of the workflow, in detail


We will run this workflow on pull requests agains main and on pushes to the main branch and run at 4:05 at night.
```
# test_and_update_cve_records.yml
on:
  push:
    branches:
      - 'main'
  pull_request:
    branches:
      - 'main'
  schedule:
    - cron: "5 4 * * *"
```

The we need to check out the code

```
jobs:
  test_and_update_cve_records:
    runs-on: ubuntu-latest
    steps:
      # Get the repository's code
      - name: Checkout
        uses: actions/checkout@v2
```

After the code is checkout out, we are going to test the CVE records


```
      # Check CVE records and publish them    
      - name: CVE RSUS check and upload
        uses: DIVD-NL/cna-bot@v1
```

The iputs that start with cve- are our CVE credentials to log in. We suggest you store these in your github secrets


```
        with: 
          cve-user        : ${{ secrets.CVE_USER }}
          cve-org         : ${{ secrets.CVE_ORG }}
          cve-api-key     : ${{ secrets.CVE_API_KEY }}
          cve-environment : test                                      # Change to prod for actual use
```

Next we want to instruct the action to only publish.update records if we have merged them into main.
```
          publish         : ${{ github.ref == 'refs/heads/main' }}    # Only publish when we merge into the main branch
```

We need to tell the action where our records live.
```
          path            : records/                                  # This is where the CVE records live
```

With this option we can ignore certain check, e.g. set it to `published_in_path` if you don't wat to check that each published CVE has a record in this directory.
```
          ignore          : ""                                        # Don't ignore any checks
```

These to items control CVE record reservation. `min-reserved` sets the minimum number of available CVE records for the (current) year. If the number of reserved records drops below this threshold the action will fail, or reserve more CVE IDs depending on the setting of `reserve`.
If `reserve` is set to a positive number, the action will reserve this number of records. If more records are needed to go back the the minimum, this ammount will be reserved instead.
```
          min-reserved    : 10                                        # Keep at least 10 reserved records (for the current year)
          reserve         : 10                                        # Reserve a minimum of 10 records at a time 
```

If the remote record does not match the local record, create a pull reuqest to update the local records. These changes should mostly be about metadata.
```
          pr              : ${{ github.event_name != 'pull_request' }}  # Create a PR when we push or run on schedule
          github-token:     ${{ secrets.GITHUB_TOKEN }}          
```

Note: If you want github actions to run on pull requests created by this action you will have to use a personal Github Access token with at least the `repo`, `org:read` and `discussion:read` scopes.

```
          expire-after    : "1y"
```
If we have reservations of 1 year before last year, in the state `RESERVED`, then automatically create a pull-request to set them to `REJECTED`.
