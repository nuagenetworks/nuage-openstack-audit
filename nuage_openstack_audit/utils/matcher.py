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
import six


class Matcher(object):

    @abstractmethod
    def entity_name(self):
        pass

    def get_mapper(self):
        return {}

    def map_to_vsd_object(self, neutron_obj):
        return {}

    def map_neutron_to_vsd(self, neutron_obj):

        # direct mapping
        mapping = self.map_to_vsd_object(neutron_obj)
        if mapping:
            return mapping

        # mapping by a mapper
        else:
            mapping = self.get_mapper()
            result = {}
            for key in neutron_obj:
                if key in mapping and key in neutron_obj:
                    for attr_mapping in mapping[key]:
                        result_key, method = attr_mapping
                        result[result_key] = method(neutron_obj[key])
            return result

    def compare(self, neutron_obj, vsd_obj):
        v_n = self.map_neutron_to_vsd(neutron_obj)
        attr_discrepancies = []
        for k in six.iterkeys(v_n):
            v_n_k = v_n[k]
            vsd_o_k = getattr(vsd_obj, k)
            if str(v_n_k) != str(vsd_o_k):
                attr_discrepancies.append((k, '{} != {}'.format(
                    v_n_k, vsd_o_k)))
        return attr_discrepancies
