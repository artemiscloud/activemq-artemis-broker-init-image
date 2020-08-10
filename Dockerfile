FROM fedora
#FROM registry.access.redhat.com/ubi7:7.8-345.1594640649

ENV HTTP_PROXY=squid.corp.redhat.com:3128
ENV HTTPS_PROXY=squid.corp.redhat.com:3128
ENV NO_PROXY=localhost,127.0.0.1,10.96.0.0/12,192.168.99.0/24,192.168.39.0/24,192.168.42.0/24

RUN python3 --version

RUN curl https://bootstrap.pypa.io/get-pip.py | python3

RUN dnf install -y pip

RUN pip install virtualenv 
RUN dnf install git -y

RUN mkdir -p /tmp/amqcfg
WORKDIR /tmp/amqcfg

RUN git clone https://github.com/gaohoward/amqcfg.git .
RUN python3 -m virtualenv -p python3 venv3

RUN ls -lrt

RUN sed -i 's/python/python3/g' ./setup.py

RUN /bin/bash -c "source venv3/bin/activate"; ./setup.py install

#RUN ./setup.py install

CMD amqcfg --help



