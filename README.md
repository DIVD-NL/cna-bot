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

Path to find CVE records in. Any \*.json file in this riectory is considered a CVE record (defaults to `.`)

### `ignore`

Comma separted list of checks to ignore.

### `min-reserved`

Minimum number of reserved records for the current year.

Action will fail if the number of records in RESERVED state drops below this amount. If `reserve` is set to a number above 0 this action will reserve this many new records.

### `reserve`

Minimum number of records to reserve in one go (0=do not make reservations)

### `pr`

Create a pull request to bring local records in line with remote records (defaults to `false`)

## Versions

For the stable version use `DIVD-NL/cna-bot@v1` (reccomended)

For the current beta version use `DIVD-NL/cna-bot@v1.3`

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
          path            : records/                                    # This is where the CVE records live
          ignore          : ""                                          # Don't ignore any checks
          min-reserved    : 10                                          # Keep at least 10 reserved records (for the current year)
          reserve         : 10                                          # Reserve a minimum of 10 records at a time 
          pr              : ${{ github.event_name != 'pull_request' }}  # Create a PR when we push or run on schedule
          github-token:     ${{ secrets.GITHUB_TOKEN }}          
```

I will explain each part of the workflow


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
