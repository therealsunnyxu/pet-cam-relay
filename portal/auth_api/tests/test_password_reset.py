from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.views import INTERNAL_RESET_SESSION_TOKEN
from django.core import mail
from django.test import Client, TestCase
from django.urls import reverse
from parameterized import parameterized
from typing import Union
import re
import base64

User: AbstractUser = get_user_model()


def flip_bit_in_token(token):
    # Add padding if missing
    missing_padding = len(token) % 4
    if missing_padding:
        token += "=" * (4 - missing_padding)
    try:
        token_bytes = base64.urlsafe_b64decode(token.encode())
    except Exception:
        # If decoding fails, fallback to utf-8 bytes
        token_bytes = token.encode()
    # Flip the first bit of the first byte (if any)
    if len(token_bytes) > 0:
        flipped = bytes([token_bytes[0] ^ 0b00000001]) + token_bytes[1:]
    else:
        flipped = token_bytes
    # Encode back to urlsafe base64, strip padding
    flipped_token = base64.urlsafe_b64encode(flipped).decode().rstrip("=")
    return flipped_token


def extract_password_reset_confirm_params_from_email(
    email: Union[str, mail.EmailMessage]
):
    email_body = ""
    if isinstance(email, str):
        email_body = email
    elif isinstance(email, mail.EmailMessage):
        email_body = email.body
    else:
        raise ValueError("Not a str or django.core.mail.EmailMessage")

    password_reset_confirm_url = reverse(
        "password_reset_confirm", args=[".+", ".+"]
    ).replace("/.+/.+/", "")
    url_regex = re.escape(password_reset_confirm_url) + r"\/.+\/.+\/"
    reset_url_match = re.search(url_regex, email_body)
    reset_url = reset_url_match.group()

    # Extract the uidb4 and token params
    param_str = reset_url.replace(password_reset_confirm_url, "")[1:-1]
    params = param_str.split("/")
    return params


def make_password_reset_request_email(
    password_reset_url, client: Client, user: AbstractUser
):
    client.post(
        password_reset_url,
        data={"email": user.email},
        content_type="application/json",
    )

    email_obj = mail.outbox[-1]
    return email_obj


class PasswordResetRequestTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.user = User.objects.create_user(
            username="testuser", password="testpass123", email="testemail@example.com"
        )
        cls.password_reset_url = reverse("password_reset")

    @parameterized.expand(
        [
            ("missing email", {}),
            ("empty email", {"email": ""}),
            ("invalid email no at", {"email": "notanemail"}),
            ("invalid email no domain", {"email": "foo@"}),
            ("invalid email no user", {"email": "@bar.com"}),
            # ("extra field", {"email": "testemail@example.com", "foo": "bar"}), # Django automatically sanitizes out invalid fields
            ("wrong field name", {"e_mail": "testemail@example.com"}),
            ("email is int", {"email": 123}),
            ("email is list", {"email": ["testemail@example.com"]}),
            ("email is dict", {"email": {"address": "testemail@example.com"}}),
            ("email is None", {"email": None}),
        ]
    )
    def test_forgot_password_invalid_input_rejects(self, name, body):
        response = self.client.post(
            self.password_reset_url,
            data=body,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_forgot_password_valid_input_creates_email(self):
        response = self.client.post(
            self.password_reset_url,
            data={"email": self.user.email},
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj)
        self.assertEqual(len(params), 2, f"Expected 2 params, got {len(params)} params")
        uidb64, token = params
        self.assertIsNotNone(uidb64)
        self.assertIsNotNone(token)


class PasswordResetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client1 = Client()
        cls.user1 = User.objects.create_user(
            username="testuser1", password="testpass123", email="testemail1@example.com"
        )
        cls.client2 = Client()
        cls.user2 = User.objects.create_user(
            username="testuser2", password="testpass123", email="testemail2@example.com"
        )
        cls.password_reset_url = reverse("password_reset")
        cls.neutral_client = Client()

    def test_swapping_uidb64_rejects(self):
        user1_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client1, self.user1
        )
        user2_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client2, self.user2
        )
        user1_uidb64, user1_token = extract_password_reset_confirm_params_from_email(
            user1_reset_email
        )
        user2_uidb64, user2_token = extract_password_reset_confirm_params_from_email(
            user2_reset_email
        )
        user1_reset_data = {"uidb64": user1_uidb64, "token": user1_token}
        user2_reset_data = {"uidb64": user2_uidb64, "token": user2_token}

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_reset_data["uidb64"], user2_reset_data["token"]],
        )
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user2_reset_data["uidb64"], user1_reset_data["token"]],
        )
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_params_in_wrong_order_rejects(self):
        user1_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client1, self.user1
        )
        user1_uidb64, user1_token = extract_password_reset_confirm_params_from_email(
            user1_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_token, user1_uidb64],
        )
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    @parameterized.expand([(True, False), (False, True), (True, True)])
    def test_params_missing_rejects(self, uidb64_missing: bool, token_missing: bool):
        user1_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client1, self.user1
        )
        user1_uidb64, user1_token = extract_password_reset_confirm_params_from_email(
            user1_reset_email
        )

        if uidb64_missing:
            user1_uidb64 = "foobar"
        if token_missing:
            user1_token = "foobar"
        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_uidb64, user1_token],
        ).replace("foobar", "")
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_token_tampered_rejects(self):
        user1_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client1, self.user1
        )
        user1_uidb64, user1_token = extract_password_reset_confirm_params_from_email(
            user1_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_uidb64, "foobar"],
        )
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(
            response.status_code // 10,
            40,
            'The token being "foobar" should have rejected, but didn\'t',
        )

        tampered_token = flip_bit_in_token(user1_token)

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_uidb64, tampered_token],
        )
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(
            response.status_code // 10,
            40,
            "Flipping a bit in the token should have rejected, but didn't",
        )

    def test_valid_params_accepts(self):
        user1_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client1, self.user1
        )
        user1_uidb64, user1_token = extract_password_reset_confirm_params_from_email(
            user1_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user1_uidb64, user1_token],
        ).replace("foobar", "")
        response = self.neutral_client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.assertEqual(
            self.neutral_client.session.get(INTERNAL_RESET_SESSION_TOKEN),
            user1_token,
            f"Session field {INTERNAL_RESET_SESSION_TOKEN} didn't match the reset token",
        )


class PasswordResetConfirmTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.user = User.objects.create_user(
            username="testuser", password="testpass123", email="testemail@example.com"
        )
        cls.password_reset_url = reverse("password_reset")

    def test_missing_internal_reset_session_token_rejects(self):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=[user_uidb64]
        )
        session = self.client.session
        session.update({INTERNAL_RESET_SESSION_TOKEN: None})
        session.save()

        response = self.client.post(
            validate_password_reset_confirm_url,
            data={
                "new_password1": "foobarfoobar123",
                "new_password2": "foobarfoobar123",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_invalid_internal_reset_session_token_rejects(self):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=[user_uidb64]
        )
        session = self.client.session
        session.update({INTERNAL_RESET_SESSION_TOKEN: "foobar"})
        session.save()

        response = self.client.post(
            validate_password_reset_confirm_url,
            data={
                "new_password1": "foobarfoobar123",
                "new_password2": "foobarfoobar123",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_missing_uidb64_rejects(self):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=["foobar"]
        ).replace("foobar", "")
        response = self.client.post(
            validate_password_reset_confirm_url,
            data={
                "new_password1": "foobarfoobar123",
                "new_password2": "foobarfoobar123",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_invalid_uidb64_rejects(self):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=["foobar"]
        )
        response = self.client.post(
            validate_password_reset_confirm_url,
            data={
                "new_password1": "foobarfoobar123",
                "new_password2": "foobarfoobar123",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    @parameterized.expand(
        [
            ("missing both", {}),
            ("missing new password1", {"new_password2": "newpass123"}),
            ("missing new password2", {"new_password1": "newpass123"}),
            ("both empty", {"new_password1": "", "new_password2": ""}),
            (
                "new password1 empty",
                {"new_password1": "", "new_password2": "newpass123"},
            ),
            (
                "new password2 empty",
                {"new_password1": "newpass123", "new_password2": ""},
            ),
            (
                "mismatch passwords",
                {"new_password1": "newpass123", "new_password2": "differentpass"},
            ),
            (
                "new password1 int",
                {"new_password1": 12345678, "new_password2": "newpass123"},
            ),
            (
                "new password2 int",
                {"new_password1": "newpass123", "new_password2": 87654321},
            ),
            (
                "new password1 list",
                {"new_password1": ["newpass123"], "new_password2": "newpass123"},
            ),
            (
                "new password2 list",
                {"new_password1": "newpass123", "new_password2": ["newpass123"]},
            ),
            (
                "new password1 dict",
                {"new_password1": {"pw": "newpass123"}, "new_password2": "newpass123"},
            ),
            (
                "new password2 dict",
                {"new_password1": "newpass123", "new_password2": {"pw": "newpass123"}},
            ),
        ]
    )
    def test_invalid_form_rejects(self, name, data: dict):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=[user_uidb64]
        )
        response = self.client.post(
            validate_password_reset_confirm_url,
            data=data,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 40)

    def test_valid_request_accepts(self):
        user_reset_email = make_password_reset_request_email(
            self.password_reset_url, self.client, self.user
        )
        user_uidb64, user_token = extract_password_reset_confirm_params_from_email(
            user_reset_email
        )

        password_reset_confirm_url = reverse(
            "password_reset_confirm",
            args=[user_uidb64, user_token],
        )
        self.client.post(
            password_reset_confirm_url,
            content_type="application/json",
        )

        new_password = "foobarfoobar123"
        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=[user_uidb64]
        )

        response = self.client.post(
            validate_password_reset_confirm_url,
            data={
                "new_password1": new_password,
                "new_password2": new_password,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))


""" 
    
    def test_valid_tokens_but_invalid_new_password(self, name, body: dict):
        response = self.client.post(
            self.password_reset_url,
            data={"email": self.user.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        password_reset_confirm_url = reverse(
            "password_reset_confirm", args=[".+", ".+"]
        ).replace("/.+/.+/", "")
        url_regex = re.escape(password_reset_confirm_url) + r"\/.+\/.+\/"
        reset_url_match = re.search(url_regex, email_obj.body)
        reset_url = reset_url_match.group()

        # Extract the uidb4 and token params
        param_str = reset_url.replace(password_reset_confirm_url, "")[1:-1]
        uidb64, token = param_str.split("/")

        # Turn the params back into a proper URL to simulate the user clicking on it
        validate_password_reset_confirm_url = reverse(
            "validate_password_reset_confirm", args=[uidb64]
        )

        # Simulate the user clicking on the link in the email
        response = self.client.post(
            validate_password_reset_confirm_url,
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.assertEqual(INTERNAL_RESET_SESSION_TOKEN, token)




class PasswordResetFlowTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser", password="testpass123", email="testemail@example.com"
        )
        self.password_reset_url = reverse("password_reset")

    def test_forgot_password_valid_sends_email(self):
        response = self.client.post(
            self.password_reset_url,
            data={"email": self.user.email},
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.assertIsNotNone(mail.outbox)

        # Make sure the email actually got sent (using locmem)
        email_obj = mail.outbox[0]
        self.assertIsNotNone(email_obj)
        self.assertIsNotNone(email_obj.body)

        # Find the password reset link in the email
        password_reset_confirm_url = reverse(
            "password_reset_confirm", args=[".+", ".+"]
        ).replace("/.+/.+/", "")
        url_regex = re.escape(password_reset_confirm_url) + r"\/.+\/.+\/"
        reset_url_match = re.search(url_regex, email_obj.body)
        self.assertIsNotNone(reset_url_match)
        reset_url = reset_url_match.group()
        self.assertNotEqual(reset_url, "")

        # Extract the uidb4 and token params
        param_str = reset_url.replace(password_reset_confirm_url, "")[1:-1]
        params = param_str.split("/")
        self.assertEqual(len(params), 2)

    def test_password_reset_flow(self):
        response = self.client.post(
            self.password_reset_url,
            data={"email": self.user.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse("password_reset_confirm", args=params)

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))


class OldPasswordResetConfirmInvalidTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.client1 = Client()
        cls.user1 = User.objects.create_user(
            username="testuser1", password="testpass123", email="testemail1@example.com"
        )
        cls.client2 = Client()
        cls.user2 = User.objects.create_user(
            username="testuser2", password="testpass123", email="testemail2@example.com"
        )
        cls.password_reset_url = reverse("password_reset")

    def test_swapping_uidb64_rejects(self):
        self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj1 = mail.outbox[0]

        self.client2.post(
            self.password_reset_url,
            data={"email": self.user2.email},
            content_type="application/json",
        )

        email_obj2 = mail.outbox[1]

        params1 = extract_password_reset_confirm_params_from_email(email_obj1.body)
        params2 = extract_password_reset_confirm_params_from_email(email_obj2.body)

        params1[0], params2[0] = params2[0], params1[0]

        password_reset_confirm_url1 = reverse("password_reset_confirm", args=params1)
        password_reset_confirm_url2 = reverse("password_reset_confirm", args=params2)

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response1 = self.client1.post(
            password_reset_confirm_url1,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response1.status_code // 10, 20)
        response2 = self.client2.post(
            password_reset_confirm_url2,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response2.status_code // 10, 20)

    def test_swapping_token_rejects(self):
        self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj1 = mail.outbox[0]

        self.client2.post(
            self.password_reset_url,
            data={"email": self.user2.email},
            content_type="application/json",
        )

        email_obj2 = mail.outbox[1]

        params1 = extract_password_reset_confirm_params_from_email(email_obj1.body)
        params2 = extract_password_reset_confirm_params_from_email(email_obj2.body)

        params1[1], params2[1] = params2[1], params1[1]

        password_reset_confirm_url1 = reverse("password_reset_confirm", args=params1)
        password_reset_confirm_url2 = reverse("password_reset_confirm", args=params2)

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response1 = self.client1.post(
            password_reset_confirm_url1,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response1.status_code // 10, 20)
        response2 = self.client2.post(
            password_reset_confirm_url2,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response2.status_code // 10, 20)

    # Don't need to test two users getting each other's tokens right
    # Because that only happens if they steal each other's emails

    def test_missing_token_rejects(self):
        response = self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse(
            "password_reset_confirm", args=[params[0], "foobar"]
        )
        password_reset_confirm_url = password_reset_confirm_url.replace("foobar/", "")

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code // 10, 20)

    def test_missing_uidb64_rejects(self):
        response = self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse(
            "password_reset_confirm", args=["foobar", params[1]]
        )
        password_reset_confirm_url = password_reset_confirm_url.replace("foobar", "")

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code // 10, 20)

    def test_tampered_token_rejects(self):
        response = self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        params[1] = params[1] + "foobar"
        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse("password_reset_confirm", args=params)
        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code // 10, 20)

    def test_tampered_uidb64_rejects(self):
        response = self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        params[0] = "foobar"
        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse("password_reset_confirm", args=params)
        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code // 10, 20)

    def test_replay_rejects(self):
        response = self.client1.post(
            self.password_reset_url,
            data={"email": self.user1.email},
            content_type="application/json",
        )

        email_obj = mail.outbox[0]

        # Find the password reset link in the email
        params = extract_password_reset_confirm_params_from_email(email_obj.body)

        # Turn the params back into a proper URL to simulate the user clicking on it
        password_reset_confirm_url = reverse("password_reset_confirm", args=params)

        # Simulate the user clicking on the link in the email
        new_password = "newpassword123"
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertEqual(response.status_code // 10, 20)

        # Simulate the user clicking on the link AGAIN
        response = self.client1.post(
            password_reset_confirm_url,
            data={"new_password1": new_password, "new_password2": new_password},
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code // 10, 20)

        # Django automatically handles invalidating old tokens because it depends on the previous password's salt
        # Just checking to make sure it actually works
"""
