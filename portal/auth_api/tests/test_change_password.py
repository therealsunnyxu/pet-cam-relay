from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.test import Client, TestCase
from django.urls import reverse
from parameterized import parameterized
import json

User: AbstractUser = get_user_model()


class ChangePasswordInvalidTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.change_password_url = reverse("user_password")
        cls.user = User.objects.create_user(username="testuser", password="testpass123")

    def setUp(self):
        self.client.login(username="testuser", password="testpass123")

    @parameterized.expand(
        [
            ("missing all", {}),
            (
                "missing old password",
                {"new_password1": "newpass123", "new_password2": "newpass123"},
            ),
            (
                "missing new password1",
                {"old_password": "testpass123", "new_password2": "newpass123"},
            ),
            (
                "missing new password2",
                {"old_password": "testpass123", "new_password1": "newpass123"},
            ),
            (
                "all empty",
                {"old_password": "", "new_password1": "", "new_password2": ""},
            ),
            (
                "old password wrong",
                {
                    "old_password": "wrongpass",
                    "new_password1": "newpass123",
                    "new_password2": "newpass123",
                },
            ),
            (
                "new passwords mismatch",
                {
                    "old_password": "testpass123",
                    "new_password1": "newpass123",
                    "new_password2": "differentpass",
                },
            ),
            (
                "new password1 empty",
                {
                    "old_password": "testpass123",
                    "new_password1": "",
                    "new_password2": "newpass123",
                },
            ),
            (
                "new password2 empty",
                {
                    "old_password": "testpass123",
                    "new_password1": "newpass123",
                    "new_password2": "",
                },
            ),
            (
                "old password empty",
                {
                    "old_password": "",
                    "new_password1": "newpass123",
                    "new_password2": "newpass123",
                },
            ),
            (
                "new passwords both empty",
                {
                    "old_password": "testpass123",
                    "new_password1": "",
                    "new_password2": "",
                },
            ),
            ("new passwords both missing", {"old_password": "testpass123"}),
            (
                "old password list",
                {
                    "old_password": [],
                    "new_password1": "newpass123",
                    "new_password2": "newpass123",
                },
            ),
            (
                "new password1 list",
                {
                    "old_password": "testpass123",
                    "new_password1": [],
                    "new_password2": "newpass123",
                },
            ),
            (
                "new password2 list",
                {
                    "old_password": "testpass123",
                    "new_password1": "newpass123",
                    "new_password2": [],
                },
            ),
            (
                "old password dict",
                {
                    "old_password": {},
                    "new_password1": "newpass123",
                    "new_password2": "newpass123",
                },
            ),
            (
                "new password1 dict",
                {
                    "old_password": "testpass123",
                    "new_password1": {},
                    "new_password2": "newpass123",
                },
            ),
            (
                "new password2 dict",
                {
                    "old_password": "testpass123",
                    "new_password1": "newpass123",
                    "new_password2": {},
                },
            ),
            (
                "fields not named like how Django likes it",
                {
                    "old_password": "testpass123",
                    "new_password": "newpass123",
                    "confirm_password": "newpass123",
                },
            ),
        ]
    )
    def test_change_password_invalid_combinations(self, name, payload):
        response = self.client.post(
            self.change_password_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)


class ChangePasswordTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.change_password_url = reverse("user_password")
        cls.user = User.objects.create_user(username="testuser", password="testpass123")

    def setUp(self):
        self.client.login(username="testuser", password="testpass123")

    def test_change_password_valid(self):
        payload = {
            "old_password": "testpass123",
            "new_password1": "newpass123",
            "new_password2": "newpass123",
        }
        response = self.client.post(
            self.change_password_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(payload["new_password1"]))
