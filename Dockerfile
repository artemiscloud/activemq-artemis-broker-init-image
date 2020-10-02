FROM registry.access.redhat.com/ubi7/python-36:1-77

RUN python3 --version

RUN curl https://bootstrap.pypa.io/get-pip.py | python3

RUN pip install virtualenv 

RUN python3 -m virtualenv -p python3 venv3
RUN source venv3/bin/activate
RUN pip install --extra-index-url  https://test.pypi.org/simple/ yacfg
RUN yacfg --help
RUN yacfg --list-profiles
