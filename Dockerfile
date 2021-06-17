FROM quay.io/artemiscloud/activemq-artemis-broker-kubernetes:0.2.3

USER root

ADD script /opt/amq-broker/script

### BEGIN REMOTE SOURCE
ARG REMOTE_SOURCE_DIR=/tmp/remote_source
ARG REMOTE_SOURCE_REF=f3a1e4393d99cc56173c593ed2d0cdfa7c87cd20
ARG REMOTE_SOURCE_REP=https://github.com/rh-messaging-qe/yacfg.git
RUN yum install -y git && yum clean all && rm -rf /var/cache/yum
RUN mkdir -p $REMOTE_SOURCE_DIR/app
RUN git clone $REMOTE_SOURCE_REP $REMOTE_SOURCE_DIR/app
RUN cd $REMOTE_SOURCE_DIR/app && git checkout $REMOTE_SOURCE_REF
### END REMOTE SOURCE
WORKDIR $REMOTE_SOURCE_DIR/app

RUN yum install -y rh-python36 rh-python36-python-jinja2 rh-python36-PyYAML && \
    yum clean all && rm -rf /var/cache/yum

RUN source /opt/rh/rh-python36/enable && python setup.py install

ENV PATH "$PATH:/opt/rh/rh-python36/root/usr/bin"
