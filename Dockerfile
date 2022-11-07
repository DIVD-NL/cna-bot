# Container image that runs your code
FROM alpine:latest

RUN apk update && apk add python3 py3-pip
RUN pip install cvelib jsonschema

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY program/* /run/
COPY entrypoint.sh /run/

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/run/entrypoint.sh"]
WORKDIR /cve
