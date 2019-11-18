#!/bin/sh
#
# Copyright (c) 2017-2018  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


i41=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ipIfStatsHCInOctets.ipv4.1`
i61=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ipIfStatsHCInOctets.ipv6.1`
o41=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ipIfStatsHCOutOctets.ipv4.1`
o61=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ipIfStatsHCOutOctets.ipv6.1`
i42=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ipIfStatsHCInOctets.ipv4.1`
i62=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ipIfStatsHCInOctets.ipv6.1`
o42=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ipIfStatsHCOutOctets.ipv4.1`
o62=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ipIfStatsHCOutOctets.ipv6.1`

in41=`echo ${i41} | cut -f2 -d' '`
in61=`echo ${i61} | cut -f2 -d' '`
out41=`echo ${o41} | cut -f2 -d' '`
out61=`echo ${o61} | cut -f2 -d' '`
in42=`echo ${i42} | cut -f2 -d' '`
in62=`echo ${i62} | cut -f2 -d' '`
out42=`echo ${o42} | cut -f2 -d' '`
out62=`echo ${o62} | cut -f2 -d' '`

#echo "${in1} ${out1} ${in2} ${out2}"

total4=$(expr \( ${in41} + ${out41} + ${in42} + ${out42} \))
total6=$(expr \( ${in61} + ${out61} + ${in62} + ${out62} \))

ototal4=0
ototal6=0
if [ -f /home/jclarke/cached_ip_stats.dat ]; then
    cache=$(cat /home/jclarke/cached_util.dat)
    ototal4=$(echo ${cache} | cut -f5 -d' ')
    ototal6=$(echo ${cache} | cut -f5 -d' ')
    cp -f /home/jclarke/cached_ip_stats.dat /home/jclarke/cached_ip_stats.dat.old
fi

if [ ${total4} -lt ${ototal4} ]; then
    total=$(expr ${total4} + ${ototal4})
fi
if [ ${total6} -lt ${ototal6} ]; then
    total=$(expr ${total6} + ${ototal6})
fi

echo "${total4} ${total6}" > /home/jclarke/cached_ip_stats.dat
