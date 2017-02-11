FROM python:3

RUN apt-get update && \
    apt-get install -y \
        libzmq-dev \
        git

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY . /app

WORKDIR /app

CMD echo "what do you want me to do?"
