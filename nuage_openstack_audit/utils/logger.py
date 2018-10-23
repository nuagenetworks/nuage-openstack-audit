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

from __future__ import print_function

import logging

LOG = None


class HeaderOne(object):
    header = '...'

    def __init__(self, s):
        self.s = s

    def __str__(self):
        return self.header + ' ' + self.s


class HeaderTwo(HeaderOne):
    header = HeaderOne.header + '....'


class HeaderThree(HeaderTwo):
    header = HeaderTwo.header + '....'


class Logger(object):
    def __init__(self):
        self.verbose = False

    @property
    def logger(self):
        return LOG if LOG else init_logging()

    def error(self, *args):
        self.logger.error(*args)
        self.stdout(*args)
        exit(1)

    def warn(self, *args):
        self.logger.warn(*args)

    def user(self, *args):
        self.stdout(*args)
        self.logger.info(*args)

    def info(self, *args):
        if self.verbose:
            self.user(*args)
        else:
            self.logger.info(*args)

    def debug(self, *args):
        self.logger.debug(*args)

    def set_verbose(self, verbose=True):
        self.verbose = verbose

    @staticmethod
    def stdout(*args):
        print(args[0] if len(args) == 1
              else str(args[0]) % tuple(arg for arg in args[1:]))


def init_logging(level='INFO', log_file=None):
    global LOG

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)

    root_logger.setLevel(level)

    file_formatter = logging.Formatter()
    hdlr = logging.FileHandler(log_file or '/dev/null')
    hdlr.setFormatter(file_formatter)
    hdlr.setLevel(logging.NOTSET)
    root_logger.addHandler(hdlr)

    file_format = '%%(asctime)s %%(levelname)s %(spaces)s%%(message)s'
    file_formatter._fmt = file_format % {'spaces': ''}

    LOG = logging.getLogger()
    return LOG


LOGGER = Logger()


def get_logger():
    return LOGGER
