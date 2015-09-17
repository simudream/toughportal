FROM centos:centos7
MAINTAINER jamiesun <jamiesun.net@gmail.com>


ADD docker/toughportal.conf /etc/toughportal.conf
ADD docker/supervisord.conf /etc/supervisord.conf
ADD docker/toughportal /usr/bin/toughportal

RUN chmod +x /usr/bin/toughportal

RUN mkdir -p /var/toughportal/data

ADD docker/privkey.pem /var/toughportal/privkey.pem
ADD docker/cacert.pem /var/toughportal/cacert.pem

RUN mkdir -p /root/.ssh
ADD docker/id_rsa  /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh
RUN chmod 600 /root/.ssh/id_rsa
RUN mkdir -p /etc/ssh
RUN echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
RUN echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config

RUN yum update -y
RUN yum install -y libffi-devel openssl openssl-devel git gcc crontabs python-devel python-setuptools
RUN yum clean all

RUN easy_install pip
RUN pip install supervisor
RUN pip install cyclone
RUN pip install requests
RUN pip install Mako==0.9.0
RUN pip install Beaker==1.6.4
RUN pip install MarkupSafe==0.18
RUN pip install PyYAML==3.10
RUN pip install Twisted==14.0.2
RUN pip install autobahn==0.9.3-3
RUN pip install bottle==0.12.7
RUN pip install six==1.8.0
RUN pip install tablib==0.10.0
RUN pip install zope.interface==4.1.1
RUN pip install pycrypto==2.6.1
RUN pip install pyOpenSSL>=0.14
RUN pip install service_identity

RUN git clone -b master git@github.com:talkincode/toughportal.git /opt/toughportal
RUN chmod +x /opt/toughportal/listen_server
RUN chmod +x /opt/toughportal/portal_server

EXPOSE 1818
EXPOSE 50100/udp

ENTRYPOINT ["/usr/bin/toughportal","start"]

