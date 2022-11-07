#!/bin/sh 
echo $#
echo $1
echo $2
echo $3
echo $4
echo $5
echo $6
echo $7
echo $8
echo $9
echo $10
#  args:
#    - ${{ inputs.path }}
#    - ${{ inputs.publish }}
#    - ${{ inputs.ignore }}
#    - ${{ inputs.min-reserved }}
#    - ${{ inputs.reserve }}

set -x
if [[ "$3" != "" ]]; then
	SKIP="--skip $3"
fi
if [[ "$4" != "" ]]; then
	RESERVED="--min-reserved $4"
fi
if [[ "$5" != "" ]]; then
	RESERVE="--reserve $5"
fi
if [[ "$CVE_USER" = "" || "$CVE_ORG" == "" || "$CVE_API_KEY" = "" || "$CVE_ENVIRONMENT" == "" ]] ; then
	echo "Authentication variables for cvelib are not set"
	exit 1
fi

./cve_check.py --path $1 $SKIP $RESERVED $RESERVE

if [[ "$2" == "true" ]]; then
	echo "Need to publish"
	./cve_publish_update.py --path $1
fi
