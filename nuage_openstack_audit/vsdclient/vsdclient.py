# Copyright 2018 NOKIA
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from abc import abstractmethod


class VsdClient(object):

    def __init__(self):
        pass

    @abstractmethod
    def verify_cms(self, id):
        pass

    def get_netpartition_by_name(self, name):
        pass

    # Firewall

    def get_firewalls(self, enterprise_id):
        pass

    def get_firewall_policies(self, enterprise_id):
        pass

    def get_firewall_rules(self, enterprise_id):
        pass

    def get_firewall_rules_by_policy(self, enterprise_id, os_policy_id):
        pass

    def get_firewall_rules_by_ids(self, enterprise_id, os_rule_ids):
        pass
