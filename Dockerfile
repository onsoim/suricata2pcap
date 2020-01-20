FROM ubuntu

RUN apt-get update && \
    apt-get upgrade -y

RUN apt-get install -y \
    git \
    python3 \
    python3-pip \
    vim

COPY . /home

WORKDIR /home

RUN git config --global user.email onsoim@gmail.com && \
    git config --global user.name onsoim

# docker build -t develop . && docker run --rm -it develop /bin/bash