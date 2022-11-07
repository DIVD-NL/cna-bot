# Container image that runs your code
FROM alpine:latest

RUN apk update && apk add python3 py3-pip
RUN pip install cvelib jsonschema

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY entrypoint.sh /entrypoint.sh

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /cve
