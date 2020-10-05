FROM registry.access.redhat.com/ubi8/ubi-minimal:8.2-349

### BEGIN REMOTE SOURCE
ARG REMOTE_SOURCE_DIR=/tmp/remote_source
ARG REMOTE_SOURCE_REF=78522019c84388eb7b88801f888018d211a69aa2
ARG REMOTE_SOURCE_REP=https://github.com/rh-messaging-qe/yacfg.git
RUN microdnf install git
RUN mkdir -p $REMOTE_SOURCE_DIR/app
RUN git clone $REMOTE_SOURCE_REP $REMOTE_SOURCE_DIR/app
RUN git -C $REMOTE_SOURCE_DIR/app checkout $REMOTE_SOURCE_REF
### END REMOTE SOURCE
WORKDIR $REMOTE_SOURCE_DIR/app

RUN microdnf install python3

RUN mkdir -p $(python3 -c 'import site; print(site.getsitepackages()[0])' | sed "s/lib64/lib/")
RUN sed -i 's/python/python3/g' ./setup.py

RUN ./setup.py install
