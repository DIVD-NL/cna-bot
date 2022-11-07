#!/bin/bash

docker build -t cve-rsus-validate-submit:local .
docker run  \
	-e CVE_ORG=$CVE_ORG \
	-e CVE_USER=$CVE_USER \
	-e CVE_EVIRONMENT=$CVE_ENVIRONMENT \
	-e CVE_API_KEY=$CVE_API_KEY \
	-v $PWD:/cve \
	-ti cve-rsus-validate-submit:local test-cves false