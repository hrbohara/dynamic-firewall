#!/usr/bin/env bash
set -e
cd -- "$(dirname -- "$0")"

python3 -u logger_server.py > logger.log 2>&1 &
logger_pid=$!

.venv/bin/python -u - > controller.log 2>&1 <<'PY' &
import logging
import os
os.environ["OSKEN_HUB_TYPE"] = "eventlet"
from os_ken.lib import hub
hub.patch(thread=False)
from os_ken import cfg
from os_ken.base import app_manager
from os_ken.controller import controller
logging.basicConfig(level=logging.INFO)
cfg.CONF(args=["--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port", "6653"])
app_manager.AppManager.run_apps(["os_ken.controller.ofp_handler", "firewall_controller"])
PY
controller_pid=$!

trap 'kill "$logger_pid" "$controller_pid" 2>/dev/null || true' EXIT
sleep 1
kill -0 "$logger_pid" "$controller_pid"

sudo mn --topo single,4 --mac \
    --controller remote,ip=127.0.0.1,port=6653 \
    --switch ovsk,protocols=OpenFlow13
