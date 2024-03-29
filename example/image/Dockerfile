ARG BUILD_FROM=ubuntu:22.04
FROM ${BUILD_FROM}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    autotools-dev \
    build-essential \
    curl \
    g++ \
    gcc \
    git \
    libffi-dev \
    libncurses5-dev \
    libssl-dev \
    make \
    vim \
    krb5-kdc \
    krb5-admin-server \
    libkrb5-dev \
    libsasl2-dev \
    libsasl2-modules-gssapi-mit \
    expect \
    iputils-ping \
    psmisc \
    openjdk-11-jdk \
    curl \
    wget


RUN apt-get clean\
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt/

RUN mkdir kerl

WORKDIR /opt/kerl

RUN curl -O https://raw.githubusercontent.com/kerl/kerl/master/kerl

RUN chmod a+x kerl

RUN ./kerl build 24.2.1

RUN ./kerl install 24.2.1 /opt/kerl/24.2.1

ENV PATH=$PATH:/opt/kerl/24.2.1/bin

RUN . /opt/kerl/24.2.1/activate

ENV LANG=C.UTF-8
#############################################
# Install Rebar3
#############################################

WORKDIR /opt/
RUN git clone https://github.com/erlang/rebar3.git

WORKDIR /opt/rebar3

RUN ./bootstrap
RUN ./rebar3 local install

#############################################
# Set Environment variables
#############################################

RUN apt-get update && apt-get install -y \
    jq

ENV PATH=$PATH:/opt/kerl:/opt/rebar3:/opt/kerl/24.2.1/bin
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

ENV kafka_version=
ENV scala_version=2.13
ENV vcs_ref=unspecified
ENV build_date=unspecified

ENV KAFKA_VERSION=2.8.1
ENV SCALA_VERSION=2.13
ENV KAFKA_HOME=/opt/kafka
ENV PATH=${PATH}:${KAFKA_HOME}/bin

COPY download-kafka.sh  /usr/bin/download-kafka.sh
COPY versions.sh  /usr/bin/versions.sh

RUN mkdir /tmp2

RUN download-kafka.sh

RUN tar xfz /tmp2/kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz -C /opt

RUN ln -s /opt/kafka_${SCALA_VERSION}-${KAFKA_VERSION} ${KAFKA_HOME}



RUN mkdir -p /var/log/kerberos
RUN mkdir p /etc/kdc
RUN mkdir -p /var/kerberos/krb5kdc/ 


WORKDIR /opt/kafka

CMD bash
