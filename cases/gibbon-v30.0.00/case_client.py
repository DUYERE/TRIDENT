#!/usr/bin/env python3
"""Small, dependency-free HTTP client for the local Gibbon case.

The case uses a disposable demo database and local-only credentials. This helper
keeps the login/CSRF handling in one place so the environment check and PoCs are
reproducible from the command line.
"""

import http.cookiejar
import os
import re
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = os.environ.get("GIBBON_BASE_URL", "http://127.0.0.1:8081").rstrip("/")
USERNAME = os.environ.get("GIBBON_USERNAME", "tridentadmin")
PASSWORD = os.environ.get("GIBBON_PASSWORD", "trident-demo-pass")
TIMEOUT = float(os.environ.get("GIBBON_TIMEOUT", "30"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GibbonClient:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.no_redirect_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect(),
        )
        for opener in (self.opener, self.no_redirect_opener):
            opener.addheaders = [
                ("User-Agent", "TRIDENT-case-client/1.0"),
                ("Accept", "text/html,application/xhtml+xml"),
            ]

    def request(self, path, data=None, method=None, follow=True):
        url = path if path.startswith("http") else self.base_url + path
        encoded = None
        if data is not None:
            encoded = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method=method)
        opener = self.opener if follow else self.no_redirect_opener
        try:
            response = opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as error:
            if follow:
                raise
            response = error
        with response:
            body = response.read()
            self.last_headers = dict(response.headers)
            return response.status, response.geturl(), body.decode("utf-8", "replace")

    def get(self, path, follow=True):
        return self.request(path, follow=follow)

    def post(self, path, data, follow=True):
        return self.request(path, data=data, method="POST", follow=follow)

    def post_multipart(self, path, fields, files, follow=True):
        """POST a multipart/form-data request; files maps field name to (filename, bytes)."""
        import uuid

        url = path if path.startswith("http") else self.base_url + path
        boundary = "----trident-%s" % uuid.uuid4().hex
        parts = []
        for name, value in fields.items():
            parts.append(("--%s\r\n" % boundary).encode("utf-8"))
            parts.append(('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode("utf-8"))
            parts.append(str(value).encode("utf-8"))
            parts.append(b"\r\n")
        for name, (filename, content) in files.items():
            parts.append(("--%s\r\n" % boundary).encode("utf-8"))
            parts.append(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (name, filename)).encode("utf-8"))
            parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
            parts.append(content)
            parts.append(b"\r\n")
        parts.append(("--%s--\r\n" % boundary).encode("utf-8"))
        body = b"".join(parts)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
        opener = self.opener if follow else self.no_redirect_opener
        try:
            response = opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as error:
            if follow:
                raise
            response = error
        with response:
            body = response.read()
            self.last_headers = dict(response.headers)
            return response.status, response.geturl(), body.decode("utf-8", "replace")

    @staticmethod
    def _hidden_value(html, name):
        match = re.search(
            r'name="%s"\s+value="([^"]*)"' % re.escape(name), html, re.I
        )
        return match.group(1) if match else ""

    def login(self):
        status, _, home = self.get("/")
        if status != 200:
            raise RuntimeError("GET / returned HTTP %s" % status)
        csrf = self._hidden_value(home, "csrftoken")
        nonce = self._hidden_value(home, "nonce")
        if not csrf or not nonce:
            raise RuntimeError("login form did not include csrftoken/nonce")
        status, url, body = self.post(
            "/login.php?",
            {
                "csrftoken": csrf,
                "nonce": nonce,
                "address": "",
                "method": "default",
                "username": USERNAME,
                "password": PASSWORD,
                "Login": "Login",
            },
        )
        if "loginForm" in body:
            raise RuntimeError("login failed (login form still present at %s)" % url)
        return status, url, body

    def authenticated_get(self, path):
        status, url, body = self.get(path)
        if "loginForm" in body:
            raise RuntimeError("not authenticated for %s (redirected to %s)" % (path, url))
        return status, url, body


if __name__ == "__main__":
    client = GibbonClient()
    status, url, body = client.login()
    print("login_status=%s final_url=%s bytes=%s" % (status, url, len(body)))
    print("authenticated=%s" % ("loginForm" not in body))
