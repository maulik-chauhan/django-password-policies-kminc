from django.test import TestCase

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

try:
    from django.core.urlresolvers import reverse
except ImportError:
    from django.urls import reverse

from django.utils import timezone

from password_policies.conf import settings
from password_policies.models import PasswordChangeRequired, PasswordHistory
from password_policies.tests.lib import (
    create_password_history,
    create_user,
    get_datetime_from_delta,
    passwords,
)


def get_response_location(location):
    if not location.startswith("http://testserver/"):
        location = urljoin("http://testserver/", location)
    return location


class PasswordPoliciesMiddlewareTest(TestCase):
    """Tests for the PasswordPoliciesMiddleware."""

    def setUp(self):
        """Set up a user and redirect URL."""
        self.user = create_user()
        self.redirect_url = "http://testserver/password/change/?next=/"

    def test_password_middleware_without_history(self):
        """Test middleware without password history for a user."""
        seconds = settings.PASSWORD_DURATION_SECONDS - 60
        self.user.date_joined = get_datetime_from_delta(timezone.now(), seconds)
        self.user.last_login = get_datetime_from_delta(timezone.now(), seconds)
        self.user.save()
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)
        self.client.logout()

    def test_password_middleware_with_history(self):
        """Test middleware with password history for a user."""
        create_password_history(self.user)
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.get(reverse("home"), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_response_location(response["Location"]), self.redirect_url)
        self.client.logout()
        PasswordHistory.objects.filter(user=self.user).delete()

    def test_password_middleware_enforced_redirect(self):
        """Test middleware enforced redirect for a user without history."""
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.get(reverse("home"), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_response_location(response["Location"]), self.redirect_url)
        self.client.logout()

    def test_password_change_required_enforced_redirect(self):
        """Test enforced redirect when password change is required."""
        seconds = settings.PASSWORD_DURATION_SECONDS - 60
        self.user.date_joined = get_datetime_from_delta(timezone.now(), seconds)
        self.user.last_login = get_datetime_from_delta(timezone.now(), seconds)
        self.user.save()
        p = PasswordChangeRequired.objects.create(user=self.user)
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.get(reverse("home"), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_response_location(response["Location"]), self.redirect_url)
        self.client.logout()
        p.delete()
