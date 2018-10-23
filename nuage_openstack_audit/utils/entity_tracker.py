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

from nuage_openstack_audit.utils.logger import Reporter


class EntityTracker(object):
    def __init__(self, name=None, tracked_entities=None):
        self.name = name
        self.tracked = len(tracked_entities) if tracked_entities else 0

    def __iadd__(self, e):
        self.tracked += 1
        return self

    def report(self, text='%d %s found', reported_as='h2'):
        getattr(Reporter(), reported_as)(text, self.tracked, self.name)


def tracked(*args):
    return EntityTracker(*args)
