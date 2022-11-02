#!/bin/bash

docker build -t cve-rsus-validate-submit:local .
docker run cve-rsus-validate-submit:local test