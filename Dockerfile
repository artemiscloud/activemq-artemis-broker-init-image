FROM registry.access.redhat.com/ubi8/ubi-minimal:8.2-349

### BEGIN REMOTE SOURCE
ARG REMOTE_SOURCE_DIR="/tmp/remote_source"
RUN microdnf install git
RUN mkdir -p $REMOTE_SOURCE_DIR/app
RUN git clone https://github.com/rh-messaging-qe/yacfg $REMOTE_SOURCE_DIR/app
RUN git -C $REMOTE_SOURCE_DIR/app checkout 78522019c84388eb7b88801f888018d211a69aa2
### END REMOTE SOURCE
WORKDIR $REMOTE_SOURCE_DIR/app

RUN microdnf install python3

RUN mkdir -p $(python3 -c 'import site; print(site.getsitepackages()[0])' | sed "s/lib64/lib/")
RUN sed -i 's/python/python3/g' ./setup.py

RUN ./setup.py install
