FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libelf-dev
COPY build/ /nettrace/
WORKDIR /nettrace
