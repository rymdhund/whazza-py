FROM python:3

RUN apt-get update && \
    apt-get install -y \
        libzmq-dev \
        git

RUN pip install pipenv

COPY Pipfile.lock /app/

WORKDIR /app

RUN pipenv install --system

COPY . /app


CMD echo "what do you want me to do?"
