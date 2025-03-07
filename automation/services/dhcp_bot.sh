#!/bin/sh

gunicorn -c dhcp_hook_gunicorn_config.py dhcp_bot:app --timeout 120 2>&1 | tee -a ~/dhcp_bot.log