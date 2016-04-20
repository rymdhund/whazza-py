FROM debian:jessie

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-pip \
        libzmq-dev \
        git

RUN mkdir /app
COPY . /app/
WORKDIR /app

RUN pip3 install -r requirements.txt

CMD echo "what do you want me to do?"
