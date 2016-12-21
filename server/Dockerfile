FROM debian:jessie

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-pip \
        libzmq-dev \
        git

RUN mkdir /app

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

COPY . /app/
WORKDIR /app

EXPOSE 5555
EXPOSE 5556

CMD python3 server.py
