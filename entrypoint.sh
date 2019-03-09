#!/bin/sh
while true; do
    flask db migrate
    if [[ "$?" == "0" ]]; then
        flask db upgrade
        break
    fi
    echo Upgrade command failed, retrying in 5 secs...
    sleep 5
done
exec flask run --host=0.0.0.0
