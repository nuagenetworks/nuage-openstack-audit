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

import pprint

from nuage_openstack_audit.utils import entity_tracker
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.utils.utils import Utils

INFO = Reporter('INFO')
WARN = Reporter('WARN')


class DeveloperModus(object):

    _is_on = False
    _developer_entity_tracker = False

    def __init__(self):

        # this constructor is the initiator to have developer functions set up;
        # the constructed instance can go out of scope once it is constructed;
        # it does not serve any purpose any longer.

        DeveloperModus._is_on = True
        WARN.report('Developer modus is on.')

        # in developer modus, extreme verbose is enabled
        WARN.logger.set_extreme_verbose()
        WARN.report('Extreme verbose is on (DEBUG to console).')

        if Utils.get_env_bool('OS_AUDIT_DEVELOPER_ENTITY_TRACKER'):
            DeveloperModus._developer_entity_tracker = True
            WARN.report('Developer entity tracker is on.')

        if Utils.get_env_bool('OS_AUDIT_DEVELOPER_TIME_TRACKER'):
            TimeIt.enable(True)
            WARN.report('Developer time tracker is on.')

    @staticmethod
    def is_on():
        return DeveloperModus._is_on

    @staticmethod
    def developer_entity_tracker_enabled():
        return DeveloperModus._developer_entity_tracker

    @staticmethod
    def tracked(*args):
        return DeveloperEntityTracker(*args)


class DeveloperEntityTracker(entity_tracker.EntityTracker):
    def __init__(self, name=None, tracked_entities=None):
        super(DeveloperEntityTracker, self).__init__(name, [])
        self.tracked = tracked_entities or []

    def __iadd__(self, e):
        self.tracked.append(e)
        return self

    @staticmethod
    def report_entities(entities):
        INFO.set_color(INFO.BLUE)
        for e in entities:
            INFO.h0(INFO.BLUE + pprint.pformat(
                e.to_dict() if hasattr(e, 'to_dict') else e, indent=2))
            INFO.newline()
        INFO.endc()

    def report(self, text='%d %s found', reported_as='h2'):
        getattr(Reporter(), reported_as)(text, len(self.tracked), self.name)
        if self.tracked:
            self.report_entities(self.tracked)
