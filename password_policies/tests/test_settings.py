import os
from distutils.version import LooseVersion

from django import get_version

# Get the current Django version
django_version = get_version()

DEBUG = False

LANGUAGES = (("en", "English"),)

LANGUAGE_CODE = "en"

USE_TZ = False

# Enable or disable internationalization machinery
USE_I18N = True

# Secret key for Django, should be unique and kept secret in production
SECRET_KEY = "fake-key"

# List of applications to be installed
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "password_policies",
]

# Database configuration, using SQLite for in-memory testing
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "TEST_NAME": ":memory:",
        "USER": "",
        "PASSWORD": "",
        "PORT": "",
    },
}

ROOT_URLCONF = "password_policies.tests.urls"

SITE_ID = 1

# Conditional template settings to maintain compatibility with Django 1.7
if LooseVersion(django_version) < LooseVersion("1.8.0"):
    TEMPLATE_DIRS = (os.path.join(os.path.dirname(__file__), "templates"),)
    TEMPLATE_CONTEXT_PROCESSORS = (
        "django.contrib.auth.context_processors.auth",
        "django.core.context_processors.debug",
        "django.core.context_processors.i18n",
        "django.contrib.messages.context_processors.messages",
        "password_policies.context_processors.password_status",
    )
else:
    TEMPLATES = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [
                os.path.join(os.path.dirname(__file__), "templates"),
            ],
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    "django.contrib.auth.context_processors.auth",
                    "django.template.context_processors.debug",
                    "django.template.context_processors.i18n",
                    "django.contrib.messages.context_processors.messages",
                    "password_policies.context_processors.password_status",
                ],
            },
        },
    ]

# Middleware configuration
MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "password_policies.middleware.PasswordChangeMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
)

# Session serializer configuration
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"

# Media URL configuration
MEDIA_URL = "/media/somewhere/"

# Default auto field configuration
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
