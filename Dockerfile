FROM quay.io/artemiscloud/activemq-artemis-broker-kubernetes:0.2.4

USER root

RUN yum install -y git && yum clean all && rm -rf /var/cache/yum

RUN yum install -y python38 python38-setuptools python38-jinja2 python38-pyyaml && \
    yum clean all && rm -rf /var/cache/yum

### BEGIN REMOTE SOURCE
ARG REMOTE_SOURCE_DIR=/tmp/remote_source
ARG REMOTE_SOURCE_REF=5b3aec6429de1e7fa82830c3a4e537d90f83def7
ARG REMOTE_SOURCE_REP=https://github.com/rh-messaging-qe/yacfg.git
RUN mkdir -p $REMOTE_SOURCE_DIR/app
RUN git clone $REMOTE_SOURCE_REP $REMOTE_SOURCE_DIR/app
RUN cd $REMOTE_SOURCE_DIR/app && git checkout $REMOTE_SOURCE_REF
### END REMOTE SOURCE
WORKDIR $REMOTE_SOURCE_DIR/app

RUN python3 -m venv /ycfg-python3
RUN source /ycfg-python3/bin/activate && \
        pip install --upgrade pip && \
        pip install poetry && \
        poetry install

ADD script /opt/amq-broker/script

ENV PATH "/ycfg-python3/bin:$PATH"
