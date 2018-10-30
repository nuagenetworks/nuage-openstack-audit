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

from nuage_openstack_audit.utils.entity_tracker \
    import set_listing_entity_tracker_as_default
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.timeit import TimeIt


class DeveloperModus(object):

    def __init__(self):

        # this constructor is the initiator for developer modus to be on;
        # the constructed instance can go out of scope once it is constructed;
        # it does not serve any purpose any longer.

        set_listing_entity_tracker_as_default(True)
        TimeIt.enable(True)
        Reporter('WARN').report('Developer modus is on')
