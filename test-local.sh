#!/bin/bash

docker build -t cve-rsus-validate-submit:local .
docker run  -v $PWD:/cve cve-rsus-validate-submit:local . false