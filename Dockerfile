FROM quay.io/artemiscloud/activemq-artemis-broker-kubernetes:0.2.4

USER root

RUN yum install -y python38 python38-setuptools python38-jinja2 python38-pyyaml && \
    yum clean all && rm -rf /var/cache/yum

RUN python3 -m venv /ycfg-python3
RUN source /ycfg-python3/bin/activate && \
        pip install --upgrade pip && \
        pip install yacfg==0.9.2

ADD script /opt/amq-broker/script

ENV PATH "/ycfg-python3/bin:$PATH"

