"""Offline regression tests: no API key or real URL submissions needed."""
import io
import json
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import server


class VirusTotalTests(unittest.TestCase):
    def report(self, **changes):
        attrs = {'last_analysis_stats': {'malicious': 0, 'suspicious': 0,
                 'harmless': 50, 'undetected': 20, 'timeout': 0},
                 'last_analysis_date': time.time()}
        attrs.update(changes)
        return {'data': {'attributes': attrs}}

    def lookup(self, report):
        with patch.object(server, 'vt_request', return_value=report) as request:
            result = server.check_url({'url': 'https://example.com/a?x=1'}, 'test-key')
            self.assertTrue(request.call_args.args[0].startswith('/urls/'))
            return result

    def test_clean_report_is_not_called_safe(self):
        result = self.lookup(self.report())
        self.assertEqual(result['status'], 'no_detections')
        self.assertIn('do not guarantee safety', result['message'])

    def test_malicious_and_suspicious_both_flag(self):
        for category in ('malicious', 'suspicious'):
            result = self.lookup(self.report(last_analysis_stats={category: 1}))
            self.assertEqual(result['status'], 'flagged')

    def test_old_clean_report_stays_unverified(self):
        self.assertEqual(self.lookup(self.report(last_analysis_date=time.time()-8*86400))['status'], 'stale')

    def test_empty_or_missing_date_stays_unknown(self):
        self.assertEqual(self.lookup(self.report(last_analysis_stats={}))['status'], 'unknown')
        self.assertEqual(self.lookup(self.report(last_analysis_date=None))['status'], 'unknown')
        self.assertEqual(self.lookup(self.report(last_analysis_stats={'timeout': 10}))['status'], 'unknown')

    def test_unknown_url_not_automatically_submitted(self):
        with patch.object(server, 'vt_request', side_effect=server.APIError(404, 'Missing')) as request:
            result = server.check_url({'url': 'https://example.com'}, 'test-key')
            self.assertEqual(result['status'], 'not_found')
            self.assertEqual(request.call_count, 1)

    def test_submission_requires_explicit_true(self):
        with patch.object(server, 'vt_request', return_value={}) as request:
            result = server.check_url({'url': 'https://example.com', 'submit': True}, 'test-key')
            self.assertEqual(result['status'], 'queued')
            self.assertEqual(request.call_args.args, ('/urls', 'test-key', {'url': 'https://example.com'}))

    def test_dangerous_schemes_rejected_before_api(self):
        with patch.object(server, 'vt_request') as request:
            for value in ['javascript:alert(1)', 'file:///secret', 'https://', 'https://example.com:bad', 'https://example.com\n']:
                with self.assertRaises(server.APIError):
                    server.check_url({'url': value}, 'test-key')
            request.assert_not_called()

    def test_auth_quota_and_timeout_errors(self):
        for status in [401, 403, 429]:
            server.REQUEST_TIMES.clear()
            error = HTTPError(server.API, status, 'error', {}, io.BytesIO())
            with patch.object(server, 'urlopen', side_effect=error):
                with self.assertRaises(server.APIError) as caught:
                    server.vt_request('/urls/test', 'secret-test-key')
                self.assertEqual(caught.exception.status, status)
                self.assertNotIn('secret-test-key', caught.exception.message)
        server.REQUEST_TIMES.clear()
        with patch.object(server, 'urlopen', side_effect=TimeoutError):
            with self.assertRaises(server.APIError) as caught:
                server.vt_request('/urls/test', 'secret-test-key')
            self.assertEqual(caught.exception.status, 502)

    def test_local_rate_limit(self):
        server.REQUEST_TIMES.clear()
        server.REQUEST_TIMES.extend([time.monotonic()] * 4)
        with patch.object(server, 'urlopen') as request:
            with self.assertRaises(server.APIError) as caught:
                server.vt_request('/urls/test', 'test-key')
            self.assertEqual(caught.exception.status, 429)
            request.assert_not_called()
        server.REQUEST_TIMES.clear()


if __name__ == '__main__':
    unittest.main()
