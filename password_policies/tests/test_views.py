from django.core import signing
from django.test import Client, TestCase, override_settings
from django.urls.base import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from password_policies.forms import PasswordPoliciesChangeForm
from password_policies.models import PasswordHistory
from password_policies.tests.lib import create_user, passwords


class PasswordChangeViewsTestCase(TestCase):
    def setUp(self):
        self.user = create_user()
        return super(PasswordChangeViewsTestCase, self).setUp()

    def test_password_change(self):
        """
        A ``GET`` to the ``password_change`` view uses the appropriate
        template and populates the password change form into the context.
        """
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.get(reverse("password_change"))
        self.assertEqual(response.status_code, 200)
        self.failUnless(
            isinstance(response.context["form"], PasswordPoliciesChangeForm)
        )
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.client.logout()

    def test_password_change_failure(self):
        """
        A ``POST`` to the ``password_change`` view with invalid data properly
        fails and issues the according error.
        """
        data = {
            "old_password": "password",
            "new_password1": "Chah+pher9k",
            "new_password2": "Chah+pher9k",
        }
        msg = "Your old password was entered incorrectly. Please enter it again."
        self.client.login(username="alice", password=passwords[-1])
        response = self.client.post(reverse("password_change"), data=data)
        self.assertEqual(response.status_code, 200)
        self.failIf(response.context["form"].is_valid())
        self.assertFormError(response, "form", field="old_password", errors=msg)
        self.client.logout()

    def test_password_change_success(self):
        """
        A ``POST`` to the ``change_email_create`` view with valid data properly
        changes the user's password, creates a new password history entry
        for the user and issues a redirect.
        """
        data = {
            "old_password": passwords[-1],
            "new_password1": "Chah+pher9k",
            "new_password2": "Chah+pher9k",
        }
        self.client.login(username="alice", password=data["old_password"])
        response = self.client.post(reverse("password_change"), data=data)
        self.assertEqual(PasswordHistory.objects.count(), 1)
        obj = PasswordHistory.objects.get()
        self.assertTrue(response.url.endswith(reverse("password_change_done")))
        obj.delete()
        self.client.logout()

    def test_password_change_confirm(self):
        signer = signing.TimestampSigner()
        var = signer.sign(self.user.password).split(":")

        timestamp = var[1]
        signature = var[2]
        uid = urlsafe_base64_encode(force_bytes(self.user.id))

        res = self.client.get(
            reverse("password_reset_confirm", args=(uid, timestamp, signature))
        )
        assert res.status_code == 200

    @override_settings(AUTH_PASSWORD_VALIDATORS=[
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
            "OPTIONS": {"min_length": 20},
        }
    ])
    def test_password_change_wrong_validators(self):
        """
        A ``POST`` to the ``change_email_create`` view with valid data properly
        changes the user's password, creates a new password history entry
        for the user and issues a redirect.
        """
        data = {
            "old_password": passwords[-1],
            "new_password1": "Chah+pher9k",
            "new_password2": "Chah+pher9k",
        }
        msg = 'This password is too short. It must contain at least 20 characters.'
        self.client.login(username="alice", password=data["old_password"])
        response = self.client.post(reverse("password_change"), data=data)
        self.assertEqual(response.status_code, 200)
        self.failIf(response.context["form"].is_valid())
        self.assertFormError(response, "form", field="new_password2", errors=msg)
        self.client.logout()

    def test_password_reset_complete(self):
        res = self.client.get(
            reverse(
                "password_reset_complete",
            )
        )
        assert res.status_code == 200


class TestLOMixinView(TestCase):
    def test_lomixinview(self):
        c = Client()
        c.get(reverse("loggedoutmixin"))
