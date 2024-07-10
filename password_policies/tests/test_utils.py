from django.test import TestCase
from django.utils import timezone
from password_policies.models import PasswordChangeRequired, PasswordHistory
from password_policies.tests.lib import create_password_history, create_user
from password_policies.utils import PasswordCheck


class PasswordPoliciesUtilsTest(TestCase):
    def setUp(self):
        self.user = create_user()
        self.check = PasswordCheck(self.user)
        create_password_history(self.user)
        super().setUp()

    def test_password_check_is_required(self):
        # By default, no change is required
        self.assertFalse(self.check.is_required())

        # Simulate a password change requirement
        PasswordChangeRequired.objects.create(user=self.user)
        self.assertTrue(self.check.is_required())

    def test_password_check_is_expired(self):
        # Verify that the password is expired after creating history
        self.assertTrue(self.check.is_expired())

        # Create a new password history to simulate a non-expired password
        PasswordHistory.objects.create(user=self.user, password="testpass")
        self.assertFalse(self.check.is_expired())
