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


i1=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ifHCInOctets.1`
o1=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.161 ifHCOutOctets.1`
i2=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ifHCInOctets.1`
o2=`/usr/local/bin/snmpget -Oq -v3 -l authPriv -u USER -a SHA -A PW -x AES -X PW 10.66.201.162 ifHCOutOctets.1`

bi1=1099215991115
bo1=187042593328
bi2=677250570
bo2=218486766

in1=`echo ${i1} | cut -f2 -d' '`
out1=`echo ${o1} | cut -f2 -d' '`
in2=`echo ${i2} | cut -f2 -d' '`
out2=`echo ${o2} | cut -f2 -d' '`

#echo "${in1} ${out1} ${in2} ${out2}"

btotal=1287
total=$(expr \( ${in1} + ${out1} + ${in2} + ${out2} \) / 1000000000)

in1=$(expr ${in1} - ${bi1})
out1=$(expr ${out1} - ${bo1})
in2=$(expr ${in2} - ${bi2})
out2=$(expr ${out2} - ${bo2})
total=$(expr ${total} - ${btotal})

oi1=0
oi2=0
oo1=0
oo2=0
ototal=0
if [ -f /home/jclarke/cached_util.dat ]; then
    cache=$(cat /home/jclarke/cached_util.dat)
    oi1=$(echo ${cache} | cut -f1 -d' ')
    oi2=$(echo ${cache} | cut -f2 -d' ')
    oo1=$(echo ${cache} | cut -f3 -d' ')
    oo2=$(echo ${cache} | cut -f4 -d' ')
    ototal=$(echo ${cache} | cut -f5 -d' ')
    cp -f /home/jclarke/cached_util.dat /home/jclarke/cached_util.dat.old
fi

if [ ${in1} -lt ${oi1} ]; then
    in1=$(expr ${in1} + ${oi1})
fi
if [ ${in2} -lt ${oi2} ]; then
    in2=$(expr ${in2} + ${oi2})
fi
if [ ${out1} -lt ${oo1} ]; then
    out1=$(expr ${out1} + ${oo1})
fi
if [ ${out2} -lt ${oo2} ]; then
    out2=$(expr ${out2} + ${oo2})
fi
if [ ${total} -lt ${ototal} ]; then
    total=$(expr ${total} + ${ototal})
fi

echo "${in1} ${in2} ${out1} ${out2} ${total}" > /home/jclarke/cached_util.dat

#echo "total = ${total}"

date=`date`

total=`/usr/local/bin/perl -MNumber::Format -e "\\\$x = new Number::Format(THOUSANDS_SEP => ' '); print \\\$x->format_number(${total})"`

cat <<EOF > /usr/local/www/apache24/data/utilization.html
<html>
  <head>
    <meta http-equiv="content-type" a="" content="text/html; charset=UTF-8">
    <meta http-equiv="refresh" content="15">
    <title>Cisco Live Melbourne Internet Usage (GigaBytes Transfered)</title>
    <style type="text/css">
p.rightpar {text-align: right; color: white;}
p.tabletitle {font-size: 30pt; color: white;}
p.headtitle {font-size: 30pt; color: white; text-align: center;}
body {font-family: "Trebuchet MS", Helvetica, sans-serif; background-color: black;}
.BannerTable {color: black; table-layout: fixed;}
.CLTable td {text-align: center; font-size: 10pt; width: 100px;}
.MainTable {color: white; table-layout: fixed; border: 0px; width: 75%; background-color: #269E7A; }
.MainTable td.bignum { font-size: 144pt; text-align: right; vertical-align: text-bottom;}
.MainTable td.smallnum { font-size: 50pt; text-align: left; vertical-align: text-bottom;}
.MainTable td.unit { font-size: 50pt; text-align: left; vertical-align: text-bottom;}
.DeviceTable { color: white; table-layout: fixed; }
    </style>
  </head>
  <body>
    <center>
      <table class="BannerTable" align="center" border="0" cellpadding="2" cellspacing="2" width="100%">
	<tbody>
	  <tr>
	    <td valign="top" width="15%">
	      <br/>
	    </td>
	    <td align="center" style="background-color: white;" valign="top"><img alt="NOCHeader" src="cl_logo.png" width="211" height="88">
	    </td>
	    <td valign="top" width="15%">
	      <p class="rightpar">Dashboard Generated: ${date}<br/>Updated
	        every FIVE minutes</p>
	    </td>
	  </tr>
	</tbody>
      </table>
    </center>
    <p class="headtitle">CiscoLive Internet WAN Traffic (Total Traffic
    Amount In+Out)</p>
    <center>
      <table class="MainTable">
	<tbody>
	  <tr>
	    <td class="bignum" style="width: 30%">${total}</td>
	    <td class="smallnum" style="width: 10%"></td>
	    <td class="unit" style="width: 20%">Gigabytes</td>
	  </tr>
	</tbody>
      </table>
    </center>
    <br/>
    <br/>
    <br/>
    <table class="DeviceTable" align="center" border="1"
					      cellpadding="2" cellspacing="2" width="40%">
      <tr>
	<th>WAN Router</th>
	<th>Input Bytes</th>
	<th>Output Bytes</th>
      </tr>
      <tr>
	<td align="left">liveau-wan-gw1</td>
	<td align="right">${in1}</td>
	<td align="right">${out1}</td>
      </tr>
      <tr>
	<td align="left">liveau-wan-gw2</td>
	<td align="right">${in2}</td>
	<td align="right">${out2}</td>
      </tr>
    </table>
    <br/>
    <br/>
    <p class="headtitle">Counter began on Monday, March 6 at 16:00
    AEDT when Registration opened.</p>
  </body>
</html>
EOF
