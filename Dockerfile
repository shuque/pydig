FROM alpine:3.12.0

RUN apk add python3 py3-pip git
RUN pip3 install requests
RUN pip3 install -e git+https://github.com/shuque/pydig.git@v1.6.7

ENTRYPOINT ["/usr/bin/pydig"]
