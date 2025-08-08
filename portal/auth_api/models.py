from django.db import models
from django.contrib.auth.models import AbstractUser
from secrets import token_urlsafe
from datetime import datetime, timedelta, timezone
from portal_config import settings
from random import randrange

MAX_OTP = (10**settings.OTP_LENGTH) - 1
GRACE_PERIOD_TIMEDELTA = timedelta(minutes=settings.OTP_GRACE_PERIOD_MINUTES)


def generate_otp():
    otp_int: int = randrange(MAX_OTP)
    return str(otp_int).zfill(settings.OTP_LENGTH)


# Create your models here.
class User(AbstractUser):
    pass
