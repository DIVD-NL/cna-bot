# Container image that runs your code
FROM alpine:latest

RUN apk update && apk add python3 py3-pip git github-cli tar
RUN python3 -m venv /run/python/venv ; . /run/python/venv/bin/activate ; pip install cvelib jsonschema python-dateutil deepdiff

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY program/* /run/
COPY schemas/* /run/schemas/
COPY entrypoint.sh /run/

ADD https://github.com/mprpic/cvelint/releases/download/v0.2.0/cvelint_Linux_x86_64.tar.gz /tmp/
RUN tar -xvzf /tmp/cvelint_Linux_x86_64.tar.gz -C /run/

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/run/entrypoint.sh"]
WORKDIR /cve
