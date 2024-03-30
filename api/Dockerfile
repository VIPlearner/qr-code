FROM python:3.12

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONOPTIMIZE 1
ENV POSTGRES_DB_URI "postgresql://user1:12345678@localhost:5432/qr-code-db"

WORKDIR /opt/app

COPY pyproject.toml poetry.lock ./

RUN apt-get update &&  \
    apt-get install -y curl build-essential git && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --upgrade pip && \
    pip install poetry && \
    poetry install

RUN docker run --name qr-code-db -e POSTGRES_USER=user1 -e POSTGRES_PASSWORD=12345678 -e POSTGRES_DB=qr-code-db -p 5432:5432 -d postgres:alpine

COPY .. .

EXPOSE 2000

CMD ["poetry", "run", "gunicorn", "--bind", "0.0.0.0:2000", "--worker-class", "gevent", "src/app:app"]