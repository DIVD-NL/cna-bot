#!/bin/bash

if [[ "$CVE_ENVIRONMENT" != "test" ]]; then
	echo "CVE_ENVIRONMENT is set to '$CVE_ENVIRONMENT'"
	echo "I refuse to run test when this is not set to 'test'"
	exit 1
fi

docker build -t cve-rsus-validate-submit:local . || exit 1

echo
echo "*** Correct CVEs ***"
echo

set -e # Fail on error

docker run  \
	-e CVE_ORG=$CVE_ORG \
	-e CVE_USER=$CVE_USER \
	-e CVE_ENVIRONMENT=$CVE_ENVIRONMENT \
	-e CVE_API_KEY=$CVE_API_KEY \
	-e CVE_PATH=test-cves \
	-e INCLUDE_RESERVATIONS=true \
	-e CREATE_MISSING=true \
	-e MIN_RESERVED=10 \
	-e RESERVE=1 \
	-v $PWD:/cve \
	-ti cve-rsus-validate-submit:local test-cves true
echo
echo "*** Error record CVEs *** (preess ctrl+c to abort)"
echo
sleep 3
docker run  \
	-e CVE_ORG=$CVE_ORG \
	-e CVE_USER=$CVE_USER \
	-e CVE_ENVIRONMENT=$CVE_ENVIRONMENT \
	-e CVE_API_KEY=$CVE_API_KEY \
	-e CVE_PATH=error-cves \
	-e INCLUDE_RESERVATIONS=true \
	-v $PWD:/cve \
	-ti cve-rsus-validate-submit:local test-cves true

