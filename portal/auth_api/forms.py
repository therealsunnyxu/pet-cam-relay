from django.forms import forms, EmailField


class ChangeEmailForm(forms.Form):
    old_email = EmailField(label="Old email")
    new_email = EmailField(label="New email")


class CustomPasswordResetForm(forms.Form):
    email = EmailField(label="Email address")
