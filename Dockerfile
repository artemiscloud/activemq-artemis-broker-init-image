FROM fedora

RUN python3 --version

RUN curl https://bootstrap.pypa.io/get-pip.py | python3

RUN dnf install -y pip

RUN pip install virtualenv 
RUN dnf install git -y

#using this one suggested by yacfg team
#RUN pip install --extra-index-url  https://test.pypi.org/simple/ yacfg

RUN mkdir -p /tmp/yacfg
WORKDIR /tmp/yacfg

RUN git clone https://github.com/rh-messaging-qe/yacfg .
RUN git checkout master
RUN git pull --rebase origin master
RUN python3 -m virtualenv -p python3 venv3
RUN sed -i 's/python/python3/g' ./setup.py
RUN /bin/bash -c "source venv3/bin/activate"; ./setup.py install; ./setup.py develop
RUN /bin/bash -c "/usr/local/bin/yacfg --list-profiles"




