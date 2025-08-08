import django
from django.apps import apps
from django.conf import settings
from django.db import connection
import os

# Forcibly set up test environment using in-memory database
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "portal_config.settings")
settings.DATABASES["default"] = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": ":memory:",
}
settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
django.setup()

# Populate the in-memory test database
with connection.schema_editor() as schema_editor:
    for model in apps.get_models():
        schema_editor.create_model(model)
