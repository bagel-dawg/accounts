FROM python:alpine

ENV TZ=US/Eastern

WORKDIR /app

RUN apk add --no-cache mariadb-connector-c-dev ;\
    apk add --no-cache --virtual .build-deps \
        tzdata \
        build-base \
        mariadb-dev ;\
    pip install mysqlclient;\
    apk del .build-deps 

COPY ./requirements.txt /app/requirements.txt

RUN pip install -r requirements.txt

COPY . /app

COPY entrypoint.sh /app/

RUN chmod +x ./entrypoint.sh

ENTRYPOINT [ "./entrypoint.sh" ]