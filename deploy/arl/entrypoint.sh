#!/usr/bin/env bash
set -euo pipefail

generated=/code/app/config.yaml
python3 - "$ARL_API_KEY" /opt/arl/config-docker.yaml "$generated" <<'PY'
import pathlib
import sys

key, source, target = sys.argv[1:]
text = pathlib.Path(source).read_text()
pathlib.Path(target).write_text(text.replace("__ARL_API_KEY__", key))
PY

case "${ARL_ROLE:-web}" in
  web)
    exec sh -c "gen_crt.sh; nginx; wait-for-it.sh arl-mongodb:27017; wait-for-it.sh arl-rabbitmq:5672; gunicorn -b 0.0.0.0:5003 app.main:arl_app -w 3 --access-logfile /code/arl_web.log --access-logformat '%({x-real-ip}i)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"'"
    ;;
  worker)
    exec sh -c "wait-for-it.sh arl-mongodb:27017; wait-for-it.sh arl-rabbitmq:5672; celery -A app.celerytask.celery worker -l info -Q arlgithub -n arlgithub -c 2 -O fair -f /code/arl_worker.log & celery -A app.celerytask.celery worker -l info -Q arltask -n arltask -c 2 -O fair -f /code/arl_worker.log"
    ;;
  scheduler)
    exec sh -c "wait-for-it.sh arl-mongodb:27017; wait-for-it.sh arl-rabbitmq:5672; python3.6 -m app.scheduler"
    ;;
  *)
    echo "unknown ARL_ROLE: ${ARL_ROLE}" >&2
    exit 1
    ;;
esac
