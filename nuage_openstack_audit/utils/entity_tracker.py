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

import abc

from nuage_openstack_audit.utils.logger import Reporter
import six

INFO = Reporter('INFO')


@six.add_metaclass(abc.ABCMeta)
class EntityTracker(object):

    def __init__(self, name=None, tracked_entities=None):
        self._name = name
        self._tracked = tracked_entities

    def name(self):
        return self._name

    def tracked(self):
        return self._tracked

    @abc.abstractmethod
    def count(self):
        pass

    @abc.abstractmethod
    def __iadd__(self, e):
        pass

    @abc.abstractmethod
    def report(self, text='%d %s found',
               reporting_level='INFO', reporter_hdr='h2'):
        pass


class CountingEntityTracker(EntityTracker):
    def __init__(self, name=None, tracked_entities=None):
        super(CountingEntityTracker, self).__init__(
            name, len(tracked_entities) if tracked_entities else 0)

    def __iadd__(self, e):
        self._tracked += 1
        return self

    def count(self):
        return self._tracked

    def report(self, text='%d %s found', level='INFO', header='h2'):
        getattr(Reporter(level), header)(text, self._tracked, self._name)


class ListingEntityTracker(EntityTracker):
    def __init__(self, name=None, tracked_entities=None):
        super(ListingEntityTracker, self).__init__(name,
                                                   tracked_entities or [])

    def __iadd__(self, e):
        self._tracked.append(e)
        return self

    def count(self):
        return len(self._tracked)

    @staticmethod
    def _report_entities(entities):
        INFO.set_color(INFO.BLUE)
        for e in entities:
            INFO.pprint(e.to_dict() if hasattr(e, 'to_dict') else e).newline()
        INFO.endc()

    def report(self, text='%d %s found', level='INFO', header='h2'):
        getattr(Reporter(level), header)(text, len(self._tracked), self._name)
        if self.tracked:
            self._report_entities(self._tracked)


def tracked_as_counting(*args):
    return CountingEntityTracker(*args)


def tracked_as_listing(*args):
    return ListingEntityTracker(*args)


DEFAULT_TO_LISTING_ENTITY_TRACKER = False


def set_listing_entity_tracker_as_default(listing_as_default=True):
    global DEFAULT_TO_LISTING_ENTITY_TRACKER
    DEFAULT_TO_LISTING_ENTITY_TRACKER = listing_as_default


def tracked(*args):
    global DEFAULT_TO_LISTING_ENTITY_TRACKER

    if DEFAULT_TO_LISTING_ENTITY_TRACKER:
        return ListingEntityTracker(*args)
    else:
        return CountingEntityTracker(*args)
