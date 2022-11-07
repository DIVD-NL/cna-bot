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
if [[ ! -z $3 ]]; then
	SKIP="--skip $3"
fi
if [[ ! -z $4 ]]; then
	RESERVED="--min-reserved $4"
fi
if [[ ! -z $5 ]]; then
	RESERVE="--reserve $5"
fi
if [[ -z $CVE_USER || -z $CVE_ORG || -z $CVE_API_KEY || -z $CVE_ENVIRONMENT ]] ; then
	echo "AUthentication variables for cvelib are not set"
	exit 1
fi

./cve_check.py --path $1 $SKIP $RESERVED $RESERVE
