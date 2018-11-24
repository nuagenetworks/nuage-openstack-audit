
from nuage_openstack_audit.utils.logger import Reporter

WARN = Reporter('WARN')


class TestMixin(object):

    @staticmethod
    def check_in(needle, haystack, message='Expected {} be in {}'):
        if needle not in haystack:
            Reporter('WARN').report(message.format(needle, haystack))
            return False
        else:
            return True

    def assert_in(self, needle, haystack, message='Expected {} be in {}'):
        if not self.check_in(needle, haystack, message):
            self.assertIn(needle, haystack, message)

    @staticmethod
    def check_equal(expected, observed,
                    message='Expected {}, got {}'):
        if expected != observed:
            Reporter('WARN').report(message.format(expected, observed))
            return False
        else:
            return True

    def assert_equal(self, expected, observed,
                     message='Expected {}, got {}'):
        if not self.check_equal(expected, observed, message):
            self.assertEqual(expected, observed, message)

    def assert_audit_report_length(self, expected_length, audit_report):
        actual_length = len(audit_report)
        if not self.check_equal(expected_length,
                                actual_length,
                                'Expected {} discrepancies, got {}'):
            WARN.pprint(audit_report)
            self.assert_equal(expected_length, actual_length)

    def assert_entities_in_sync(self, expected, observed):
        self.assert_equal(expected, observed,
                          'Expected {} entities in sync, got {}')
