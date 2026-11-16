"""Local QR Studio server. Python 3.9+, no third-party dependencies."""
import base64
from collections import deque
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
API = 'https://www.virustotal.com/api/v3'
LIMIT_LOCK = threading.Lock()
REQUEST_TIMES = deque()


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def validate_url(value):
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise APIError(400, 'Enter a valid HTTP or HTTPS URL.')
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise APIError(400, 'URL contains control characters.')
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError()
        parsed.port
    except ValueError:
        raise APIError(400, 'Only valid HTTP and HTTPS URLs can be checked.')
    return value


def vt_request(path, key, body=None):
    # Respect the usual public API limit; do not silently retry or block threads.
    with LIMIT_LOCK:
        now = time.monotonic()
        while REQUEST_TIMES and now - REQUEST_TIMES[0] >= 60:
            REQUEST_TIMES.popleft()
        if len(REQUEST_TIMES) >= 4:
            raise APIError(429, 'Local API limit reached. Wait one minute and try again.')
        REQUEST_TIMES.append(now)
    headers = {'x-apikey': key, 'Accept': 'application/json'}
    data = None
    if body is not None:
        data = urlencode(body).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    request = Request(API + path, data=data, headers=headers)
    try:
        with urlopen(request, timeout=15) as response:
            return json.load(response)
    except HTTPError as error:
        messages = {
            401: 'VirusTotal rejected the API key. Check VT_API_KEY and restart.',
            403: 'Your VirusTotal key does not have access to this operation.',
            404: 'VirusTotal has no report for this URL.',
            429: 'VirusTotal quota exceeded. Wait before checking again.',
        }
        raise APIError(error.code if error.code in messages else 502,
                       messages.get(error.code, 'VirusTotal is temporarily unavailable.'))
    except (URLError, TimeoutError, OSError, ValueError):
        raise APIError(502, 'Could not reach VirusTotal. Link safety is unverified.')


def check_url(payload, key):
    url = validate_url(payload.get('url'))
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    report_url = 'https://www.virustotal.com/gui/url/' + identifier
    if payload.get('submit') is True:
        vt_request('/urls', key, {'url': url})
        return {'status': 'queued', 'report_url': report_url,
                'message': 'URL submitted. Analysis may take a minute; check the report again later.'}
    try:
        result = vt_request('/urls/' + identifier, key)
    except APIError as error:
        if error.status == 404:
            return {'status': 'not_found', 'report_url': report_url,
                    'message': 'VirusTotal has no report. This URL is unverified.'}
        raise
    attributes = result.get('data', {}).get('attributes', {})
    raw_stats = attributes.get('last_analysis_stats')
    if not isinstance(raw_stats, dict) or not raw_stats:
        return {'status': 'unknown', 'report_url': report_url,
                'message': 'No completed analysis is available. This URL is unverified.'}
    stats = {name: max(0, int(raw_stats.get(name, 0))) for name in
             ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout')}
    analyzed = attributes.get('last_analysis_date')
    if not isinstance(analyzed, (int, float)) or analyzed <= 0:
        analyzed = None
    if stats['malicious'] or stats['suspicious']:
        status = 'flagged'
    elif not analyzed or not sum(stats[name] for name in ('harmless', 'undetected')):
        status = 'unknown'
    elif time.time() - analyzed > 7 * 86400:
        status = 'stale'
    else:
        status = 'no_detections'
    return {'status': status, 'stats': stats,
            'last_analysis': datetime.fromtimestamp(analyzed, timezone.utc).isoformat() if analyzed else None,
            'report_url': report_url,
            'message': 'VirusTotal results describe a past analysis and do not guarantee safety.'}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, *args):
        pass  # Do not write decoded URLs or their query strings to logs.

    def trusted_request(self):
        host = self.headers.get('Host', '')
        if host not in ('127.0.0.1:8000', 'localhost:8000'):
            return False
        origin = self.headers.get('Origin')
        return origin in (None, 'http://' + host)

    def json_response(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_POST(self):
        if not self.trusted_request():
            return self.json_response(403, {'message': 'Only the local app can use this endpoint.'})
        if self.path != '/api/virustotal/check':
            return self.json_response(404, {'message': 'Not found.'})
        try:
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise APIError(415, 'Expected JSON.')
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise APIError(413, 'Request is too large or empty.')
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise APIError(400, 'Expected a JSON object.')
            key = os.environ.get('VT_API_KEY', '').strip()
            if not key:
                raise APIError(503, 'VirusTotal is not configured. Set VT_API_KEY and restart server.py.')
            self.json_response(200, check_url(payload, key))
        except APIError as error:
            self.json_response(error.status, {'status': 'unavailable', 'message': error.message})
        except (ValueError, TypeError, OverflowError):
            self.json_response(400, {'status': 'unavailable', 'message': 'Invalid request or analysis data.'})

    def do_GET(self):
        if not self.trusted_request():
            return self.json_response(403, {'message': 'Use http://localhost:8000.'})
        # Serve only app assets, never .env, Python files, Git data or directory listings.
        path = urlsplit(self.path).path
        if path not in ('/', '/index.html', '/style.css', '/app.js'):
            return self.json_response(404, {'message': 'Not found.'})
        super().do_GET()

    def do_HEAD(self):
        if not self.trusted_request():
            return self.json_response(403, {'message': 'Use http://localhost:8000.'})
        if urlsplit(self.path).path not in ('/', '/index.html', '/style.css', '/app.js'):
            return self.json_response(404, {'message': 'Not found.'})
        super().do_HEAD()


if __name__ == '__main__':
    print('QR Studio: http://localhost:8000 — Ctrl+C to stop')
    print('VirusTotal: ' + ('configured' if os.environ.get('VT_API_KEY') else 'not configured (set VT_API_KEY)'))
    ThreadingHTTPServer(('127.0.0.1', 8000), Handler).serve_forever()
