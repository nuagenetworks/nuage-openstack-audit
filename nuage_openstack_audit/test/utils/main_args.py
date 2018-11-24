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
from nuage_openstack_audit.utils.utils import Utils

USER = Reporter('USER')

DEVELOPER_MODUS = Utils.get_env_bool('OS_AUDIT_DEVELOPER_MODUS')
VERBOSE = Utils.get_env_bool('OS_AUDIT_VERBOSE')
EXTREME_VERBOSE = Utils.get_env_bool('OS_AUDIT_EXTREME_VERBOSE')
LOG_LEVEL = Utils.get_env_var('OS_AUDIT_LOG_LEVEL', 'INFO')
DEBUG = 'debug' in LOG_LEVEL.lower()


USER.set_color(USER.BLUE)
if DEVELOPER_MODUS:
    USER.report('Developer modus is on, '
                'which implies debug & extreme verbose')
else:
    USER.report('VERBOSE is %s, set OS_AUDIT_VERBOSE to change', VERBOSE)
    if VERBOSE or EXTREME_VERBOSE:
        USER.report('Extreme VERBOSE is %s, '
                    'set OS_AUDIT_EXTREME_VERBOSE to change', EXTREME_VERBOSE)
    USER.report('DEBUG is %s, set OS_AUDIT_LOG_LEVEL to change', DEBUG)
USER.set_color(USER.ENDC).newline()


class MainArgs(object):
    def __init__(self, resource, report=None):
        assert resource in ['fwaas', 'security_group', 'all']

        self.resource = resource
        self.report = report
        self.verbose = VERBOSE
        self.extreme_verbose = EXTREME_VERBOSE
        self.debug = DEBUG
