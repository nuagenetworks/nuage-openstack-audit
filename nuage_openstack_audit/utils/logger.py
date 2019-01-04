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
import pprint

LOGGING = None


class LoggerBase(object):

    RED = '\033[91m'  # light red (red is 31)
    GREEN = '\033[92m'  # light green (green is 32)
    YELLOW = '\033[93m'  # light yellow (yellow is 33)
    BLUE = '\033[94m'  # light blue (blue is 34)
    MAGENTA = '\033[95m'  # light magenta (magenta is 35)

    HEADER = MAGENTA
    DEBUG = BLUE
    EMPHASIS = GREEN
    WARNING = YELLOW
    FAIL = RED
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def no_end(kwargs):
    if 'end' in kwargs:
        del kwargs['end']  # python logging does not support end= parameter
    return kwargs


class Logger(LoggerBase):

    def __init__(self, verbose=False, extreme_verbose=False):
        # verbose indicates that INFO will be copied to console,
        # if reported (level >= INFO)
        self.verbose = verbose or extreme_verbose

        # extreme_verbose indicates that DEBUG will be copied to console,
        # if reported (level >= DEBUG)
        self.extreme_verbose = extreme_verbose

    def set_verbose(self, verbose=True):
        self.verbose = verbose

    def set_extreme_verbose(self, extreme_verbose=True):
        self.extreme_verbose = extreme_verbose
        if not self.verbose and extreme_verbose:
            self.verbose = True

    @staticmethod
    def init_logging(level='INFO', log_file=None):
        global LOGGING

        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)

        root_logger.setLevel(level)

        file_formatter = logging.Formatter()
        handler = logging.FileHandler(log_file or '/dev/null')
        handler.setFormatter(file_formatter)
        handler.setLevel(logging.NOTSET)
        root_logger.addHandler(handler)

        file_format = '%%(asctime)s %%(levelname)s %(spaces)s%%(message)s'
        file_formatter._fmt = file_format % {'spaces': ''}

        LOGGING = logging.getLogger()
        return LOGGING

    @property
    def logger(self):
        return LOGGING if LOGGING else Logger.init_logging()

    @staticmethod
    def no_end(kwargs):
        if 'end' in kwargs:
            del kwargs['end']
        return kwargs

    def error(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(logging.ERROR):
            self.stdout(Logger.FAIL + msg + Logger.ENDC, *args, **kwargs)
        self.logger.error(msg, *args, **no_end(kwargs))

    def warn(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(logging.WARN):
            self.stdout(Logger.WARNING + msg + Logger.ENDC, *args, **kwargs)
        self.logger.warn(msg, *args, **no_end(kwargs))

    def emphasis(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(logging.INFO):
            self.stdout(Reporter.EMPHASIS + msg + Reporter.ENDC,
                        *args, **kwargs)
        self.logger.info(msg, *args, **no_end(kwargs))

    def user(self, msg, *args, **kwargs):
        self.stdout(msg, *args, **kwargs)
        self.logger.info(msg, *args, **no_end(kwargs))

    def info(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(logging.INFO) and self.verbose:
            self.stdout(msg, *args, **kwargs)
        self.logger.info(msg, *args, **no_end(kwargs))

    def debug(self, msg, *args, **kwargs):
        if self.logger.isEnabledFor(logging.DEBUG) and self.extreme_verbose:
            self.stdout(Reporter.DEBUG + msg + Reporter.ENDC, *args, **kwargs)
        self.logger.debug(msg, *args, **no_end(kwargs))

    @staticmethod
    def stdout(msg, *args, **kwargs):
        if args:
            print(msg % tuple(args), **kwargs)
        else:
            print(msg, **kwargs)


LOGGER = Logger()


def get_logger():
    return LOGGER


class Reporter(LoggerBase):

    def __init__(self, level='INFO'):
        self.logger = get_logger()
        self.level = level.lower()
        self._report = getattr(self.logger, self.level)

    def report(self, msg, *args, **kwargs):
        self._report(msg, *args, **kwargs)
        return self  # returning self allows for chaining, e.g.
        #              Reporter().newline().set_color(green).h0('OK').endc()

    def pprint(self, some_dict):
        return self.report(pprint.pformat(some_dict, indent=2))

    def newline(self):
        return self.report('')

    def set_color(self, color):
        return self.report(color, end='')

    def endc(self):  # end of color
        return self.set_color(Reporter.ENDC)

    def coloured(self, color, msg, *args, **kwargs):
        return self.set_color(color).report(msg, *args, **kwargs).endc()

    def green(self, msg, *args, **kwargs):
        return self.coloured(Reporter.GREEN, msg, *args, **kwargs)

    def blue(self, msg, *args, **kwargs):
        return self.coloured(Reporter.BLUE, msg, *args, **kwargs)

    def yellow(self, msg, *args, **kwargs):
        return self.coloured(Reporter.YELLOW, msg, *args, **kwargs)

    def red(self, msg, *args, **kwargs):
        return self.coloured(Reporter.RED, msg, *args, **kwargs)

    def h0(self, msg, *args, **kwargs):
        return self.report(msg, *args, **kwargs)

    def h1(self, msg, *args, **kwargs):
        return self.report('... ' + msg, *args, **kwargs)

    def h2(self, msg, *args, **kwargs):
        return self.report('....... ' + msg, *args, **kwargs)

    def h3(self, msg, *args, **kwargs):
        return self.report('........... ' + msg, *args, **kwargs)
