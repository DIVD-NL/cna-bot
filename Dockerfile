# Container image that runs your code
FROM alpine:latest

RUN apk update && apk add python3 py3-pip git github-cli  tar
RUN pip install cvelib jsonschema python-dateutil deepdiff

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY program/* /run/
COPY entrypoint.sh /run/

ADD https://github.com/mprpic/cvelint/releases/download/v0.1.0/cvelint_Linux_x86_64.tar.gz /tmp/
RUN tar -xvzf /tmp/cvelint_Linux_x86_64.tar.gz -C /run/

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/run/entrypoint.sh"]
WORKDIR /cve
