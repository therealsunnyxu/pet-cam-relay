from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.test import Client, TestCase
from django.urls import reverse
from parameterized import parameterized
import json

User: AbstractUser = get_user_model()


class LoginHandlerTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.login_url = reverse("login")
        cls.user = User.objects.create_user(username="testuser", password="testpass123")

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
        self.assertEqual(response.status_code // 10, 20)

    @parameterized.expand(
        [
            ("missing username", {"password": "testpass123"}),
            ("missing password", {"username": "testuser"}),
            ("empty username", {"username": "", "password": "testpass123"}),
            ("empty password", {"username": "testuser", "password": ""}),
            (
                "username not a string (int)",
                {"username": 123, "password": "testpass123"},
            ),
            ("password not a string (int)", {"username": "testuser", "password": 456}),
            (
                "username not a string (float)",
                {"username": 1.23, "password": "testpass123"},
            ),
            (
                "password not a string (float)",
                {"username": "testuser", "password": 4.56},
            ),
            ("username is None", {"username": None, "password": "testpass123"}),
            ("password is None", {"username": "testuser", "password": None}),
            ("username is bool True", {"username": True, "password": "testpass123"}),
            ("username is bool False", {"username": False, "password": "testpass123"}),
            ("password is bool True", {"username": "testuser", "password": True}),
            ("password is bool False", {"username": "testuser", "password": False}),
            ("username is list", {"username": ["testuser"], "password": "testpass123"}),
            ("password is list", {"username": "testuser", "password": ["testpass123"]}),
            ("username is empty list", {"username": [], "password": "testpass123"}),
            ("password is empty list", {"username": "testuser", "password": []}),
            (
                "username is dict",
                {"username": {"u": "testuser"}, "password": "testpass123"},
            ),
            (
                "password is dict",
                {"username": "testuser", "password": {"p": "testpass123"}},
            ),
            ("username is empty dict", {"username": {}, "password": "testpass123"}),
            ("password is empty dict", {"username": "testuser", "password": {}}),
            ("both missing", {}),
            ("both not strings (int)", {"username": 123, "password": 456}),
            ("both not strings (float)", {"username": 1.23, "password": 4.56}),
            ("both not strings (bool)", {"username": True, "password": False}),
            ("both not strings (None)", {"username": None, "password": None}),
            ("both not strings (list)", {"username": [], "password": []}),
            ("both not strings (dict)", {"username": {}, "password": {}}),
        ]
    )
    def test_login_invalid_data_returns_400(self, name, payload):
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)
