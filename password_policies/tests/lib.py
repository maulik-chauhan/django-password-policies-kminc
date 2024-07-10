from datetime import timedelta
from random import randint

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone

from password_policies.conf import settings
from password_policies.models import PasswordHistory

passwords = [
    'ohl"ahn8aiSu',
    "la]ePhae1Ies",
    "xareW&ang4sh",
    "haea_d7AiWoo",
    "Eim9Co:e0aev",
    "Ve2eereil>ai",
    "Aengae]t:ie4",
    "ao6Lei+Hip=u",
    "zo!i8aigai{L",
    "Ju8AhGhoo(p?",
    "xieY6fohv>ei",
    "Elu1ie*z5aa3",
    "ooDei1Hoo+Ru",
    "Xohth3ohpu$o",
    "ia)D5AP7sie$",
    "heeb8aeCh-ae",
]


def create_user(
    username="alice",
    email="alice@example.com",
    raw_password=None,
    date_joined=None,
    last_login=None,
    commit=True,
):
    """Creates a non-staff user with dynamically generated properties.

    Args:
        username (str): Username of the user. Default is "alice".
        email (str): Email of the user. Default is "alice@example.com".
        raw_password (str, optional): Raw password for the user. Default is the last password in the passwords list.
        date_joined (datetime, optional): Date the user joined. Default is dynamically generated.
        last_login (datetime, optional): Last login time. Default is the same as date_joined.
        commit (bool): Whether to save the user instance. Default is True.

    Returns:
        user: A User instance.
    """
    count = settings.PASSWORD_HISTORY_COUNT
    duration = settings.PASSWORD_DURATION_SECONDS
    if not raw_password:
        raw_password = passwords[-1]
    if not date_joined:
        rind = randint(0, (duration // count + 1))
        seconds = (count * duration + rind) * 2
        date_joined = get_datetime_from_delta(timezone.now(), seconds)
    if not last_login:
        last_login = date_joined
    user = get_user_model()(
        username=username,
        email=email,
        is_active=True,
        last_login=last_login,
        date_joined=date_joined,
    )
    user.set_password(raw_password)
    if commit:
        user.save()
    return user


def create_password_history(user, password_list=None):
    """Creates password history for a user.

    Args:
        user: A User instance.
        password_list (list, optional): List of raw passwords. Default is the predefined passwords list.
    """
    duration = settings.PASSWORD_DURATION_SECONDS
    if password_list is None:
        password_list = passwords
    seconds = len(password_list) * duration
    created = get_datetime_from_delta(timezone.now(), seconds)
    for raw_password in password_list:
        password = make_password(raw_password)
        entry = PasswordHistory.objects.create(password=password, user=user)
        entry.created = created
        entry.save()
        created = get_datetime_from_delta(created, duration * -1)


def get_datetime_from_delta(value, seconds):
    """Returns a Datetime value after subtracting given seconds.

    Args:
        value (datetime): The base datetime value.
        seconds (int): The number of seconds to subtract.

    Returns:
        datetime: The resulting datetime.
    """
    return value - timedelta(seconds=seconds)
