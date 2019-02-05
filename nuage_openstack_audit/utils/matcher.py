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
        mapped_vsd_obj = self.map_neutron_to_vsd(neutron_obj)
        # Loop over the vsd object in a deterministic order so discrepancies
        # are also reported consistently (improves testability)
        for attr_name in sorted(mapped_vsd_obj.keys()):
            mapped_value = mapped_vsd_obj[attr_name]
            original_value = getattr(vsd_obj, attr_name)
            if str(mapped_value) != str(original_value):
                yield (attr_name, '{} != {}'.format(mapped_value,
                                                    original_value))
