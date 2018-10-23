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

import six


class AuditorException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        try:
            super(BaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            super(BaseException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return unicode(self.msg)

    def __str__(self):
        return self.msg


class NuageBadRequest(AuditorException):
    message = "Bad request: %(msg)s"


class NuageAPIException(AuditorException):
    message = "Nuage API: %(msg)s"
