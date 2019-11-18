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

from ucsmsdk.ucshandle import UcsHandle
from ucsmsdk.mometa.fabric.FabricVlan import FabricVlan
from ucsmsdk.mometa.vnic.VnicEtherIf import VnicEtherIf
import os
import pprint


class UCSVlans():

    _handle = None

    def _login(self):
        if self._handle is not None:
            return self._handle

        handle = UcsHandle(self.device, self.username,
                           os.environ['NXOS_ADMIN_PW'])

        handle.login()
        self._handle = handle

        return self._handle

    def deploy_fabric_vlan(self):
        try:
            handle = self._login()

            v = FabricVlan(parent_mo_or_dn='fabric/lan',
                           name=self.vname, id=str(self.vid))
            handle.add_mo(v)
            handle.commit()
        except Exception as e:
            print('Error adding VLAN {} to fabric on {}: {}'.format(
                self.vid, self.device, e))
            return False

        return True

    def delete_fabric_vlan(self):
        try:
            handle = self._login()
            filter_str = '(id, "{}")'.format(self.vid)
            v = handle.query_classid(
                class_id='FabricVlan', filter_str=filter_str)
            if len(v) != 1:
                raise Exception(
                    'Got {} elements with VLAN ID {}'.format(len(v), self.vid))
            handle.remove_mo(v[0])
            handle.commit()
        except Exception as e:
            print('Error deleting VLAN {} on {}: {}'.format(
                self.vid, self.device, e))
            return False

        return True

    def deploy_lan_policy(self):
        try:
            handle = self._login()

            mos = []

            for vnic in (self.vnic_a, self.vnic_b):
                try:
                    v = VnicEtherIf(
                        parent_mo_or_dn='org-root/lan-conn-pol-{}/ether-{}'.format(self.policy, vnic), name=self.vname)
                    handle.add_mo(v)
                    handle.commit()
                    mos.append(v)
                except Exception as e:
                    print('Error adding VLAN {} to LAN connectivity policy {}/{} on {}: {}'.format(
                        self.vname, self.policy, vnic, self.device, e))
                    if len(mos) > 0:
                        try:
                            handle.delete_mo(v)
                            handle.commit()
                        except Exception as ie:
                            print('Error removing VLAN {} from LAN connectivity policy {} on {}: {}'.format(
                                self.vname, self.policy, self.device, ie))
                    return False
        except Exception as le:
            print('Error logging into {}: {}'.format(self.device, le))
            return False

        return True

    def logout(self):
        if self._handle is None:
            return
        try:
            self._handle.logout()
        except:
            pass
