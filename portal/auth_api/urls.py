from django.urls import path
from . import views

urlpatterns = [
    path("login", views.login_handler, name="login"),
    path("logout", views.logout_handler, name="logout"),
    path("token/csrf", views.csrf_token_handler, name="token_csrf"),
    path("user/email", views.change_email_handler, name="user_email"),
    path("user/password", views.change_password_handler, name="user_password"),
    path("password/reset", views.password_reset_request_handler, name="password_reset"),
    path(
        "password/reset/confirm/<uidb64>/set-password/",
        views.validate_password_reset_confirm_handler,
        name="validate_password_reset_confirm",
    ),
    path(
        "password/reset/confirm/<uidb64>/<token>/",
        views.password_reset_confirm_handler,
        name="password_reset_confirm",
    ),
    path("check", views.auth_check_handler, name="auth-check"),
]
