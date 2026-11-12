#!/usr/bin/env bash
set -euo pipefail

# No built-in credentials. Missing values fail loudly instead of silently
# starting ARL with a guessable password (see .env.example / README.md).
missing=()
for var in ARL_API_KEY MONGO_ROOT_USER MONGO_ROOT_PASSWORD RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS; do
  if [ -z "${!var:-}" ]; then missing+=("$var"); fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ARL entrypoint: missing required environment variables: ${missing[*]}" >&2
  echo "Fill them in .env (see .env.example) before enabling the arl profile." >&2
  exit 1
fi
if [[ ! "$ARL_API_KEY" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ARL entrypoint: ARL_API_KEY must use only A-Z a-z 0-9 . _ - (generated token)" >&2
  exit 1
fi

generated=/code/app/config.yaml
python3 - "$ARL_API_KEY" "$MONGO_ROOT_USER" "$MONGO_ROOT_PASSWORD" "$RABBITMQ_DEFAULT_USER" "$RABBITMQ_DEFAULT_PASS" /opt/arl/config-docker.yaml "$generated" <<'PY'
import pathlib
import sys
import urllib.parse

key, mongo_user, mongo_pass, rabbit_user, rabbit_pass, source, target = sys.argv[1:]
quote = lambda value: urllib.parse.quote(value, safe="")
text = pathlib.Path(source).read_text()
for placeholder, value in {
    "__ARL_API_KEY__": key,
    "__MONGO_USER__": quote(mongo_user),
    "__MONGO_PASS__": quote(mongo_pass),
    "__RABBIT_USER__": quote(rabbit_user),
    "__RABBIT_PASS__": quote(rabbit_pass),
}.items():
    text = text.replace(placeholder, value)
pathlib.Path(target).write_text(text)
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
