import sys
from typing import Any, override

from django.conf import settings as LazySettingsGetter
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int
from portal_config import settings as SiteSettings
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class SiteSpecificTokenTool(PasswordResetTokenGenerator):
    @override
    def __init__(self, settings: Any):
        super().__init__()
        self._settings = settings
        self._secret = self._get_secret()
        self._secret_fallbacks = self._get_fallbacks()
    
    @override
    def _get_secret(self):
        return self._secret or LazySettingsGetter.SECRET_KEY or self._settings.SECRET_KEY

    @override
    def _get_fallbacks(self):
        if self._secret_fallbacks is None:
            return LazySettingsGetter.SECRET_KEY_FALLBACKS or self._settings.SECRET_KEY_FALLBACKS
        return self._secret_fallbacks

    # The code from the original token generator, but the LazySettings swapped with SiteSettings
    @override
    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user.
        """
        if not (user and token):
            return False
        # Parse the token
        try:
            ts_b36, _ = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        token = token.replace("=", "")
        for secret in [self._secret, *self._secret_fallbacks]:
            if constant_time_compare(
                self._make_token_with_timestamp(user, ts, secret),
                token,
            ):
                break
        else:
            return False

        # Check the timestamp is within limit.
        if (self._num_seconds(self._now()) - ts) > self._settings.PASSWORD_RESET_TIMEOUT:
            return False

        return True

token_generator = SiteSpecificTokenTool(SiteSettings)
