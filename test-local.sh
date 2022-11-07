#!/bin/bash

if [[ "$CVE_ENVIRONMENT" != "test" ]]; then
	echo "CVE_ENVIRONMENT is set to '$CVE_ENVIRONMENT'"
	echo "I refuse to run test when this is not set to 'test'"
	exit 1
fi

docker build -t cve-rsus-validate-submit:local .
docker run  \
	-e CVE_ORG=$CVE_ORG \
	-e CVE_USER=$CVE_USER \
	-e CVE_ENVIRONMENT=$CVE_ENVIRONMENT \
	-e CVE_API_KEY=$CVE_API_KEY \
	-v $PWD:/cve \
	-ti cve-rsus-validate-submit:local test-cves true
