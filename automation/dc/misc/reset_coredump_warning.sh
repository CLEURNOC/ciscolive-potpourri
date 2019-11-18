#!/bin/sh

export VI_SERVER="cl-vcenter.ciscolive.network"

if [ -z "${VI_USERNAME}" -o -z "${VI_PASSWORD}" ]; then
    echo "You must set the VI_USERNAME and VI_PASSWORD environment variables first."
    exit 1
fi

hosts=$(/home/jclarke/getHosts.pl)

for h in ${hosts}; do
    vicfg-advcfg -h ${h} --set 0 UserVars.SuppressCoredumpWarning >/dev/null
    if [ $? != 0 ]; then
	echo "Failed to unset suppression warning for ${h}!"
	continue
    fi
    vicfg-advcfg -h ${h} --set 1 UserVars.SuppressCoredumpWarning > /dev/null
    if [ $? != 0 ]; then
	echo "Failed to set suppression warning for ${h}!"
    fi
done
