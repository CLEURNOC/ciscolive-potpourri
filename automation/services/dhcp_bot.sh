#!/bin/sh

gunicorn -c dhcp_hook_gunicorn_config.py dhcp_bot:app