#!/bin/sh 
#  args:
#    - ${{ inputs.path }}
#    - ${{ inputs.publish }}
#    - ${{ inputs.ignore }}
#    - ${{ inputs.min-reserved }}
#    - ${{ inputs.reserve }}

# Fail if we encounter an error
set -e

# Process command line arguments
if [[ "$3" != "" ]]; then
	SKIP="--skip $3"
fi
if [[ "$4" != "" ]]; then
	RESERVED="--min-reserved $4"
fi
if [[ "$5" != "" ]]; then
	RESERVE="--reserve $5"
fi

# Check if we have CVE Services credentials
if [[ "$CVE_USER" = "" || "$CVE_ORG" == "" || "$CVE_API_KEY" = "" || "$CVE_ENVIRONMENT" == "" ]] ; then
	echo "Authentication variables for cvelib are not set."
	exit 1
fi

# Need to declare this directory safe, to get git commit time
git config --global --add safe.directory $PWD

# Check the CVE records
echo "*** Checking CVE records ***"
/run/cve_check.py --path $1 $SKIP $RESERVED $RESERVE --schema /run/cve50.json

if [[ "$2" == "true" ]]; then
	echo "*** Publishing/updating CVE records ***"
	/run/cve_publish_update.py --path $1
fi
