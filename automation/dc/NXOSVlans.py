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

from ncclient import manager
import json
import xmltodict
import xml.dom.minidom
import logging
import os
import pprint

# logging.basicConfig(level=logging.DEBUG)


class NXOSVlans():

    vlan_get = '''
<show xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
<vlan>
<id>
<vlan-id>{}</vlan-id>
</id>
</vlan>
</show>
    '''

    vlan_add = '''
<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
<configure xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
<__XML__MODE__exec_configure>
<vlan>
<vlan-id-create-delete>
  <__XML__PARAM_value>{}</__XML__PARAM_value>
  <__XML__MODE_vlan>
    <name>
      <vlan-name>{}</vlan-name>
    </name>
    <state>
      <vstate>active</vstate>
    </state>
    <no>
      <shutdown/>
    </no>
  </__XML__MODE_vlan>
</vlan-id-create-delete>
</vlan>
</__XML__MODE__exec_configure>
</configure>
</config>
    '''

    vlan_delete = '''
<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <configure xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
    <__XML__MODE__exec_configure>
      <no>
        <vlan>
          <vlan-id-create-delete>{}</vlan-id-create-delete>
        </vlan>
      </no>
    </__XML__MODE__exec_configure>
  </configure>
</config>
    '''

    vlan_port_add = '''
<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <configure>
    <__XML__MODE__exec_configure>
      <interface>
        <{}>
          <interface>{}</interface>
          <__XML__MODE_if-eth-{}-switch>
            <switchport>
              <trunk>
                <allowed>
                  <vlan>
                    <add>
                      <add-vlans>{}</add-vlans>
                    </add>
                  </vlan>
                </allowed>
              </trunk>
            </switchport>
          </__XML__MODE_if-eth-{}-switch>
        </{}>
      </interface>
    </__XML__MODE__exec_configure>
  </configure>
</config>
    '''

    vlan_port_delete = '''
<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <configure>
    <__XML__MODE__exec_configure>
      <interface>
        <{}>
          <interface>{}</interface>
          <__XML__MODE_if-eth-{}-switch>
            <switchport>
              <trunk>
                <allowed>
                  <vlan>
                    <removed>
                      <remove-vlans>{}</remove-vlans>
                    </remove>
                  </vlan>
                </allowed>
              </trunk>
            </switchport>
          </__XML__MODE_if-eth-{}-switch>
        </{}>
      </interface>
    </__XML__MODE__exec_configure>
  </configure>
</config>
    '''

    def deploy_l2_vlan(self):
        with manager.connect_ssh(host=self.device, port=22, username=self.username, hostkey_verify=False, password=os.environ['NXOS_ADMIN_PW'], device_params={'name': 'nexus'}) as m:

            # See if the VLAN currently exists.
            try:
                res = m.get(('subtree', self.vlan_get.format(self.vid)))
                resd = xmltodict.parse(res.data_xml)
                if '__XML__OPT_Cmd_show_vlan_id___readonly__' in resd['data']['show']['vlan']['id']['vlan-id']:
                    print('Error: VLAN {} already exists on {}'.format(
                        self.vid, self.device))
                    return False
            except Exception as e:
                print('Error getting VLAN {} from device {}: {}'.format(
                    self.vid, self.device, e))
                return False

            # Create L2 VLAN.
            try:
                res = m.edit_config(
                    target='running', config=self.vlan_add.format(self.vid, self.vname))
            except Exception as e:
                print('Error adding VLAN {} to device {}: {}'.format(
                    self.vid, self.device, e))
                return False

            # Add L2 VLAN to trunk ports
            if self.trunks:
                good_config = False
                for trunk in self.trunks:
                    rem = re.match(
                        r'(ethernet|port-channel)(\d+)', trunk, re.I)
                    if not rem:
                        print(
                            'Error: trunk port {} is not a valid port name'.format(trunk))
                        continue
                    pname = rem.group(1).lower()
                    try:
                        m.edit_config(target='running', config=self.vlan_port_add.format(
                            pname, rem.group(2), pname, self.vid, pname, pname))
                        good_config = True
                    except Exception as e:
                        print('Error adding VLAN {} to port {}: {}'.format(
                            self.vid, trunk, e))
                        continue

                if not good_config:
                    print('Error: Failed to add VLAN {} to any trunk ports on device {}'.format(
                        self.vid, self.device))
                    return False

        return True

    def delete_l2_vlan(self):
        with manager.connect_ssh(host=self.device, port=22, username=self.username, hostkey_verify=False, password=os.environ['NXOS_ADMIN_PW'], device_params={'name': 'nexus'}) as m:
            try:
                m.edit_config(target='running',
                              config=self.vlan_delete.format(self.vid))
            except Exception as e:
                print('Error deleteing VLAN {} from device {}: {}'.format(
                    self.vid, self.device, e))
                return False

        return True

    # XXX: This config is very specific to Cisco Live Europe
    def deploy_svi(self):
        with manager.connect_ssh(host=self.device, port=22, username=self.username, hostkey_verify=False, password=os.environ['NXOS_ADMIN_PW'], device_params={'name': 'nexus'}) as m:
            cmds = ['config t', 'no int vlan{}'.format(self.vid), 'int vlan{}'.format(self.vid), 'description {}'.format(
                self.description), 'no shutdown', 'no ip redirects', 'ip address {}'.format(self.ipv4), 'ip ospf network point-to-point', 'ip router ospf 1 area 0.0.0.0']
            if self.ipv6:
                cmds += ['ipv6 address {}'.format(
                    self.ipv6), 'no ipv6 redirects', 'ipv6 router ospfv3 1 area 0.0.0.0']
            if self.hsrpv4:
                cmds += ['no ip arp gratuitous hsrp duplicate', 'hsrp version 2', 'hsrp 1', 'authentication md5 key-chain HSRP_KEY', 'preempt',
                         'priority {}'.format(self.hsrp_priority), 'timers 1 3', 'ip {}'.format(self.hsrpv4), 'track 3 decrement 20']
            if self.hsrpv6:
                cmds += ['hsrp 2 ipv6', 'authentication md5 key-chain HSRP_KEY', 'preempt', 'priority {}'.format(
                    self.hsrp_priority), 'timers 1 3', 'ip {}'.format(self.hsrpv6), 'track 5 decrement 20']

            # print(pprint.pprint(cmds))

            try:
                m.exec_command(cmds)
            except Exception as e:
                print('Error adding SVI for VLAN {} to device {}: {}'.format(
                    self.vid, self.device, e))
                return False

        return True

    def write_config(self):
        with manager.connect_ssh(host=self.device, port=22, username=self.username, hostkey_verify=False, password=os.environ['NXOS_ADMIN_PW'], device_params={'name': 'nexus'}) as m:
            try:
                m.exec_command(['copy running startup'])
            except Exception as e:
                print('Error copying running config to startup on {}: {}'.format(
                    self.device, e))
                return False
        return True
