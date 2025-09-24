from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.views import (
    PasswordResetConfirmView,
    INTERNAL_RESET_SESSION_TOKEN,
)
from django.db.models import QuerySet
from django.forms import ValidationError, forms
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from auth_api.forms import ChangeEmailForm
from portal_config import settings
from typing import Union, Any
import json

User: AbstractUser = get_user_model()


def get_data_from_json_or_formdata(request: HttpRequest):
    data: dict = None
    if request.content_type == "application/json":
        data_str = request.body.decode("utf-8").strip()
        if len(data_str) == 0:
            return {}
        try:
            data = json.loads(data_str)
        except Exception as e:
            pass
    elif request.content_type in [
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ]:
        try:
            data = request.POST
        except Exception as e:
            pass

    return data


def merge_form_errors(form: forms.Form):
    form_errors: dict = dict(form.errors)
    non_field_errors: list = form.non_field_errors()
    if len(non_field_errors) > 0:
        form.errors["non_field_errors"] = non_field_errors

    return form_errors


@require_http_methods(["POST"])
def login_handler(request: HttpRequest):
    data: dict = get_data_from_json_or_formdata(request)
    if data is None or len(data.keys()) == 0:
        return HttpResponse(content="Form data is malformed or missing", status=400)

    form: AuthenticationForm = AuthenticationForm(request, data=data)

    if not form.is_valid():
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=401)

    username: str = str(form.cleaned_data.get("username"))
    password: str = str(form.cleaned_data.get("password"))
    user: AbstractUser = authenticate(username=username, password=password)
    # need to call authenticate again to get the user obj even though form.is_valid() calls it
    # because it doesn't return the user object
    if user is None or user.id is None:
        return JsonResponse(form.get_invalid_login_error(), status=401)

    login(request, user)

    return HttpResponse("Logged in", status=200)


@require_http_methods(["POST"])
def logout_handler(request: HttpRequest):
    logout(request)
    return HttpResponse(status=200)


@require_http_methods(["GET"])
def csrf_token_handler(request: HttpRequest):
    token = get_token(request)
    res = HttpResponse(status=200)
    res.set_cookie("csrftoken", token)
    return res


@require_http_methods(["POST"])
def change_email_handler(request: HttpRequest):
    user: AbstractUser = request.user

    if (user is None) or (user.id is None) or (user.is_authenticated == False):
        return HttpResponse(status=401)

    data: dict = get_data_from_json_or_formdata(request)
    if data is None or len(data.keys()) == 0:
        return HttpResponse(content="Form data is malformed or missing", status=400)

    form: ChangeEmailForm = ChangeEmailForm(data)

    if not form.is_valid():
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=401)

    old_email: str = str(form.cleaned_data.get("old_email"))
    new_email: str = str(form.cleaned_data.get("new_email"))
    # Assumed to not be blank because by default, EmailField required is True and strip is True

    if old_email == new_email:
        return HttpResponse("New email cannot be the same as the old email", status=400)

    actual_old_email: str = str(user.email).strip()

    if actual_old_email != old_email:
        return HttpResponse(
            content="Old email does not match current email in system", status=401
        )

    # Need to manually change and save user's email
    # because ChangeEmailForm is a custom form with no special capabilities
    user.email = new_email
    user.save()

    return HttpResponse(status=200)


@require_http_methods(["POST"])
def change_password_handler(request: HttpRequest):
    user: AbstractUser = request.user

    if (user is None) or (user.id is None) or (user.is_authenticated == False):
        return HttpResponse(status=401)

    data: dict = get_data_from_json_or_formdata(request)
    if data is None or len(data.keys()) == 0:
        return HttpResponse(content="Form data is malformed or missing", status=400)

    form: PasswordChangeForm = PasswordChangeForm(user, data)

    if not form.is_valid():
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=401)

    try:
        form.clean_old_password()
    except ValidationError:
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=401)

    try:
        form.clean()
    except ValidationError:
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=400)

    form.save()  # PasswordChangeForm comes with methods to save password changes

    return HttpResponse(status=200)


@require_http_methods(["POST"])
def password_reset_request_handler(request: HttpRequest):
    data: dict = get_data_from_json_or_formdata(request)
    if data is None or len(data.keys()) == 0:
        return HttpResponse(content="Form data is malformed or missing", status=400)

    form: PasswordResetForm = PasswordResetForm(data)
    if not form.is_valid():
        errors: dict = merge_form_errors(form)
        return JsonResponse(
            errors, status=400
        )  # Only rejects if the emails are invalid formats, not if the email actually exists

    form.save(request=request, use_https=settings.USE_HTTPS)
    # TODO: change the email template so that it points to the separate frontend
    # or just force a redirect to the frontend in the link to the route
    return HttpResponse(status=200)
    # The form save will succeed regardless if the email actually exists, because of an internal for loop
    # that just doesn't do anything if there's no email
    # Good for preventing guessing attacks


def get_user_from_password_reset_params(uidb64: str, token: str) -> AbstractUser:
    try:
        uidb64 = str(uidb64)
        token = str(token)
    except Exception:
        raise ValidationError(
            "The URL path must contain 'uidb64' and 'token' parameters", code=400
        )

    # Verify that the uidb4 and token are valid
    PasswordResetConfirmTool = (
        PasswordResetConfirmView()
    )  # use the functions inside the view instead of using the view
    user: AbstractUser = PasswordResetConfirmTool.get_user(uidb64)

    is_valid_token = PasswordResetConfirmTool.token_generator.check_token(user, token)
    if (user is None) or (user.id is None) or (not is_valid_token):
        raise ValidationError("Invalid password reset request", code=400)

    return user


@csrf_protect
@require_http_methods(["POST"])
def password_reset_confirm_handler(request: HttpRequest, uidb64: str, token: str):
    user: AbstractUser = None
    try:
        user = get_user_from_password_reset_params(uidb64, token)
    except ValidationError as e:
        msg = e.message
        code = e.code
        if msg is not None and code is not None:
            return HttpResponse(content=msg, status=code)
        return HttpResponse(status=400)
    except Exception:
        return HttpResponse(status=500)

    request.session[INTERNAL_RESET_SESSION_TOKEN] = token
    # Save the one time password reset token in the db under the AnonymousUser
    # autogenerated by Django when accessing this
    # so that the frontend doesn't carry it twice
    return HttpResponse(status=200)


@csrf_protect
@require_http_methods(["POST"])
def validate_password_reset_confirm_handler(request: HttpRequest, uidb64: str):
    user: AbstractUser = None
    try:
        token: Union[Any, None] = request.session.get(INTERNAL_RESET_SESSION_TOKEN)
        user = get_user_from_password_reset_params(uidb64, token)
        # User validation will fail if token is none or the wrong type
    except ValidationError as e:
        msg = e.message
        code = e.code
        if msg is not None and code is not None:
            return HttpResponse(content=msg, status=code)
        return HttpResponse(status=400)
    except Exception:
        return HttpResponse(status=500)

    # Check that the new password form is valid
    data: dict = get_data_from_json_or_formdata(request)
    if data is None or len(data.keys()) == 0:
        return HttpResponse(content="Form data is malformed or missing", status=400)

    form: SetPasswordForm = SetPasswordForm(user, data)

    if not form.is_valid():
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=400)

    try:
        form.clean()
    except ValidationError:
        errors: dict = merge_form_errors(form)
        return JsonResponse(errors, status=400)

    form.save()  # SetPasswordForm comes with methods to save password changes

    return HttpResponse(status=200)


@csrf_exempt
def auth_check_handler(request: HttpRequest):
    if request.user is None or request.user.id is None:
        # Django's automatic AnonymousUser doesn't have an id
        return HttpResponse(status=401)

    return HttpResponse(status=200)
