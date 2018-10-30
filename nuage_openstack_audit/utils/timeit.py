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

import time

from nuage_openstack_audit.utils import logger

DEBUG = logger.Reporter('DEBUG')


class TimeIt(object):

    enabled = False

    @staticmethod
    def enable(enable=True):
        TimeIt.enabled = enable

    @staticmethod
    def timeit(method):
        def timed(*args, **kw):
            ts = time.time()
            result = method(*args, **kw)
            te = time.time()
            DEBUG.h2(
                '=== %s.%s took %s secs ===',
                args[0].__class__.__name__, method.__name__, int(te - ts))
            return result

        if TimeIt.enabled:
            return timed
        else:
            return method
