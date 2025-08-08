from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.http import HttpRequest
from django.test import Client, TestCase
from django.urls import reverse
from parameterized import parameterized
from auth_api.views import get_data_from_json_or_formdata

User: AbstractUser = get_user_model()


class MIMETypeTestCase(TestCase):
    @parameterized.expand(
        [
            ("text/plain", "text/plain", b"hello world"),
            ("application/octet-stream", "application/octet-stream", b"\x00\x01\x02"),
            ("image/png", "image/png", b"\x89PNG\r\n\x1a\n"),
            ("no content type", None, b"no content type"),
        ]
    )
    def test_non_formlike_mime_types(self, name, content_type, body):

        request = HttpRequest()
        request.method = "POST"
        request._body = body
        if content_type is not None:
            request.META["CONTENT_TYPE"] = content_type
            request.content_type = content_type
        else:
            # Django's HttpRequest.content_type defaults to None if not set
            request.content_type = None

        data = get_data_from_json_or_formdata(request)
        self.assertIsNone(data)

    @parameterized.expand(
        [
            ("empty json", "application/json", b""),
            ("empty json brackets", "application/json", b"{}"),
            ("empty form-urlencoded", "application/x-www-form-urlencoded", b""),
            ("empty multipart", "multipart/form-data", b""),
        ]
    )
    def test_empty_valid_mime_types(self, name, content_type, body):
        request = HttpRequest()
        request.method = "POST"
        request._body = body
        request.META["CONTENT_TYPE"] = content_type
        request.content_type = content_type

        data = get_data_from_json_or_formdata(request)
        # Should not be None, but an empty dict (or QueryDict)
        self.assertIsNotNone(data)
        self.assertEqual(dict(data), {})

    # No need to test malformed multipart or url-encoded forms because QueryDict handles malformed data


class MalformedDataTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.login_url = reverse("login")

    # Only testing the login route because the other routes share the same form data conversion logic
    @parameterized.expand(
        [
            ("missing equals", "application/x-www-form-urlencoded", "usernamepassword"),
            ("only key", "application/x-www-form-urlencoded", "username="),
            ("only value", "application/x-www-form-urlencoded", "=password"),
            ("no pairs", "application/x-www-form-urlencoded", "&"),
            (
                "malformed pair",
                "application/x-www-form-urlencoded",
                "username=admin&=password",
            ),
            ("empty body", "application/x-www-form-urlencoded", ""),
            (
                "missing boundary",
                "multipart/form-data",
                '------WebKitFormBoundary\r\nContent-Disposition: form-data; name="username"\r\n\r\nadmin\r\n',
            ),
            ("no headers", "multipart/form-data", "admin"),
            (
                "malformed headers",
                "multipart/form-data",
                '------WebKitFormBoundary\r\nContent-Disposition form-data; name="username"\r\n\r\nadmin\r\n',
            ),
            ("empty multipart", "multipart/form-data", ""),
        ]
    )
    def test_login_malformed_form_data(self, name, content_type, body):
        # Django test client expects dict for data, so we use the generic client.post with content_type and raw data
        response = self.client.post(
            self.login_url,
            data=body.encode() if isinstance(body, str) else body,
            content_type=content_type,
        )
        self.assertEqual(response.status_code // 10, 40)

        @parameterized.expand(
            [
                (
                    "json valid login",
                    "application/json",
                    '{"username": "testuser", "password": "testpass123"}',
                ),
                (
                    "urlencoded valid login",
                    "application/x-www-form-urlencoded",
                    "username=testuser&password=testpass123",
                ),
                (
                    "multipart valid login",
                    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                    (
                        "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                        'Content-Disposition: form-data; name="username"\r\n\r\n'
                        "testuser\r\n"
                        "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                        'Content-Disposition: form-data; name="password"\r\n\r\n'
                        "testpass123\r\n"
                        "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
                    ),
                ),
            ]
        )
        def test_login_valid_data_returns_successfully(self, name, content_type, body):
            response = self.client.post(
                self.login_url,
                data=body.encode() if isinstance(body, str) else body,
                content_type=content_type,
            )
            self.assertEquals(response.status_code // 10, 20)
