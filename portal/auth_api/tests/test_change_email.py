from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.test import Client, TestCase
from django.urls import reverse
from parameterized import parameterized
import json

User: AbstractUser = get_user_model()


class ChangeEmailInvalidTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.change_email_url = reverse("user_email")
        cls.user = User.objects.create_user(
            username="testuser", password="testpass123", email="test@example.com"
        )

    def setUp(self):
        self.client.login(username="testuser", password="testpass123")

    @parameterized.expand(
        [
            (
                "old email wrong",
                {"old_email": "wrong@example.com", "new_email": "new@example.com"},
            ),
            ("old email none", {"old_email": None, "new_email": "new@example.com"}),
            ("new email none", {"old_email": "test@example.com", "new_email": None}),
            ("both none", {"old_email": None, "new_email": None}),
            ("old email empty", {"old_email": "", "new_email": "new@example.com"}),
            ("new email empty", {"old_email": "test@example.com", "new_email": ""}),
            ("both empty", {"old_email": "", "new_email": ""}),
            ("old email int", {"old_email": 123, "new_email": "new@example.com"}),
            ("new email int", {"old_email": "test@example.com", "new_email": 456}),
            (
                "old email list",
                {"old_email": ["test@example.com"], "new_email": "new@example.com"},
            ),
            (
                "new email list",
                {"old_email": "test@example.com", "new_email": ["new@example.com"]},
            ),
            (
                "old email dict",
                {
                    "old_email": {"email": "test@example.com"},
                    "new_email": "new@example.com",
                },
            ),
            (
                "new email dict",
                {
                    "old_email": "test@example.com",
                    "new_email": {"email": "new@example.com"},
                },
            ),
            ("both list", {"old_email": [], "new_email": []}),
            ("both dict", {"old_email": {}, "new_email": {}}),
            ("missing old email", {"new_email": "new@example.com"}),
            ("missing new email", {"old_email": "test@example.com"}),
            ("both missing", {}),
            (
                "both emails the same",
                {"old_email": "test@example.com", "new_email": "test@example.com"},
            ),
        ]
    )
    def test_change_email_invalid_combinations(self, name, payload):
        response = self.client.post(
            self.change_email_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)


class ChangeEmailTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.change_email_url = reverse("user_email")
        cls.user = User.objects.create_user(
            username="testuser", password="testpass123", email="test@example.com"
        )

    def setUp(self):
        self.client.login(username="testuser", password="testpass123")

    def test_change_email_valid(self):
        payload = {"old_email": "test@example.com", "new_email": "newemail@example.com"}
        response = self.client.post(
            self.change_email_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "newemail@example.com")
