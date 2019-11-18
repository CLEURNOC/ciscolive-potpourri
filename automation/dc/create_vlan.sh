#!/usr/bin/env bash
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


function usage() {
  echo "$0: [-d] -v <VLAN_ID> -n <VLAN_NAME> [-t <TRUNK_PORT1[,TRUNK_PORT2[,...]]] [-s [-D <SVI_DESCRIPTION>] -4 <SVI_IPV4_3_OCTETS> -m <SVI_IPV4_CIDR> [-6 <SVI_IPV6_8_WORDS> -M <SVI_IPV6_LEN>] [-r <HSRP_IPV4_VIRTUAL_IP] [-R <HSRP_IPV6_VIRTUAL_IP]]"
  exit 1
}

. ./dc.cfg

export PERL_LWP_SSL_VERIFY_HOSTNAME=0

delete_vlan=0
vid=-1
vname=""
svi=0
svi_descr=""
ipv4=""
cidr=""
ipv6=""
plen=""
hsrpv4=""
hsrpv6=""
trunks=""

while getopts ":v:n:s4:6:m:M:dD:r:R:t:" opt; do
  case $opt in
    d)
      delete_vlan=1
    ;;
    v)
      vid=$OPTARG
    ;;
    n)
      vname=$OPTARG
    ;;
    s)
      svi=1
    ;;
    D)
      svi_descr=$OPTARG
    ;;
    4)
      ipv4=$OPTARG
    ;;
    m)
      cidr=$OPTARG
    ;;
    6)
      ipv6=$OPTARG
    ;;
    M)
      plen=$OPTARG
    ;;
    r)
      hsrpv4=$OPTARG
    ;;
    R)
      hsrpv6=$OPTARG
    ;;
    t)
      trunks=$OPTARG
    ;;
    :)
      echo "Option -${OPTARG} requires an argument"
      usage
    ;;
    \?)
      echo "Invalid option, -${OPTARG}"
      usage
    ;;
  esac
done

if [ ${vid} = "-1" ]; then
  echo "Error: VLAN ID is required"
  usage
fi

if [ -z "${vname}" ]; then
  echo "Error: VLAN name is required"
  usage
fi

if [ ${svi} -eq 1 -a ${delete_vlan} -eq 0 ]; then
  if [ -z "${ipv4}" ]; then
    echo "Error: SVI IPv4 address is required"
    usage
  fi
  if [ -z "${cidr}" ]; then
    echo "Error: SVI IPv4 CIDR bits are required"
    usage
  fi
  if [ -n "${ipv6}" -a -z "${plen}" ]; then
    echo "Error: IPv6 prefix length is required with IPv6 address"
    usage
  fi
  if [ -n "${hsrpv6}" -a -z "${ipv6}" ]; then
    echo "Error: IPv6 address is required if an HSRP IPv6 address is provided"
    usage
  fi
fi

if [ ${delete_vlan} = 1 ]; then
  echo -n "Are you sure you want to delete VLAN ${vid} (${vname}): [y/N]? "
  read resp
  if echo ${resp} | grep -qvE '^[Yy]'; then
    exit 0
  fi
fi

if [ -z "${VI_USERNAME}" ]; then
  VI_USERNAME=${ADMIN_USERNAME}
fi
export VI_USERNAME

if [ -z "${ADMIN_PASSWORD}" ]; then
  echo "Error: Environment variable ADMIN_PASSWORD must be set to the password for ${ADMIN_USERNAME}"
  exit 1
fi

if [ -z "${NXOS_ADMIN_PW}" ]; then
  NXOS_ADMIN_PW=${ADMIN_PASSWORD}
fi
export NXOS_ADMIN_PW

if [ -z "${UCS_ADMIN_PW}" ]; then
  UCS_ADMIN_PW=${ADMIN_PASSWORD}
fi
export UCS_ADMIN_PW

for sw in ${SWITCHES}; do
  old_IFS=${IFS}
  IFS=","
  sw_parts=(${sw})
  hn=${sw_parts[0]}
  pri=${sw_parts[1]}
  v4=${sw_parts[2]}
  v6=${sw_parts[3]}

  #echo "${hn} : ${pri} : ${v4} : ${v6}"
  IFS=${old_IFS}

  if [ ${delete_vlan} -eq 1 ]; then
    echo -n "Deleting VLAN ${vid} from switch ${hn}..."
    nxos_add_delete_vlan.py -D -v ${vid} -d ${hn} -u ${ADMIN_USERNAME}
    if [ $? = 0 ]; then
      echo "DONE."
    else
      echo "ERROR."
    fi
  else
    args="-v ${vid} -n ${vname} -d ${hn} -u ${ADMIN_USERNAME}"
    if [ -n "${trunks}" ]; then
      old_IFS=${IFS}
      IFS=","
      args="${args} -t"
      for trunk in ${trunks}; do
        args="${args} ${trunk}"
      done
      IFS=${old_IFS}
    fi
    if [ ${svi} -eq 1 ]; then
      args="${args} -s -4 ${ipv4}.${v4}/${cidr}"
      if [ -n "${svi_descr}" ]; then
        args="${args} -e '${svi_descr}'"
      fi
      if [ -n "${ipv6}" ]; then
        args="${args} -6 ${ipv6}::${v6}/${plen}"
      fi
      if [ -n "${hsrpv4}" ]; then
        args="${args} -p ${pri} -r ${hsrpv4}"
      fi
      if [ -n "${hsrpv6}" ]; then
        args="${args} -R ${hsrpv6}"
      fi
    fi
    echo -n "Adding VLAN ${vid} to switch ${hn}..."
    nxos_add_delete_vlan.py ${args}
    if [ $? = 0 ]; then
      echo "DONE."
    else
      echo "ERROR."
    fi
  fi
done

for ucs in ${UCSES}; do
  old_IFS=${IFS}
  IFS=","
  ucs_parts=(${ucs})
  hn=${ucs_parts[0]}
  vnica=${ucs_parts[1]}
  vnicb=${ucs_parts[2]}
  policy=${ucs_parts[3]}

  #echo "${hn} : ${vnica} : ${vnicb} : ${policy}"
  IFS=${old_IFS}

  if [ ${delete_vlan} = 1 ]; then
    echo -n "Deleting VLAN ${vid} from UCS ${hn}..."
    ucs_add_delete_vlan.py -D -v ${vid} -d ${hn} -u ${ADMIN_USERNAME}
    if [ $? = 0 ]; then
      echo "DONE."
    else
      echo "ERROR."
    fi
  else
    args="-v ${vid} -n ${vname} -d ${hn} -u ${ADMIN_USERNAME} -p ${policy} -a ${vnica} -b ${vnicb}"
    echo -n "Adding VLAN ${vid} to UCS ${hn}..."
    ucs_add_delete_vlan.py ${args}
    if [ $? = 0 ]; then
      echo "DONE."
    else
      echo "ERROR."
    fi
  fi
done

for host in ${VMHOSTS}; do
  old_IFS=${IFS}
  IFS=","
  host_parts=(${host})
  hn=${host_parts[0]}
  vsw=${host_parts[1]}

  #echo "${hn} : ${vsw}"
  IFS=${old_IFS}

  if [ ${delete_vlan} = 1 ]; then
    echo -n "Deleting VLAN ${vid} from VM host ${hn}..."
    vicfg-vswitch --server ${VCENTER} --vihost ${hn} --username ${ADMIN_USERNAME} -D ${vname} ${vsw}
    if [ $? = 0 ]; then
      echo "DONE."
    else
      echo "ERROR."
    fi
  else
    echo -n "Adding VLAN ${vid} to VM host ${hn}..."
    vicfg-vswitch --server ${VCENTER} --vihost ${hn} --username ${ADMIN_USERNAME} -A ${vname} ${vsw}
    if [ $? = 0 ]; then
      vicfg-vswitch --server ${VCENTER} --vihost ${hn} --username ${ADMIN_USERNAME} -v ${vid} -p ${vname} ${vsw}
      if [ $? = 0 ]; then
        echo "DONE."
      else
        echo "ERROR."
      fi
    else
      echo "ERROR."
    fi
  fi
done
