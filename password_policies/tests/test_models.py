from django.test import TestCase

from password_policies.conf import settings
from password_policies.models import PasswordHistory
from password_policies.tests.lib import create_password_history, create_user, passwords


class PasswordHistoryModelTestCase(TestCase):
    """Tests for the PasswordHistory model."""

    def setUp(self):
        """Set up a user and password history for testing."""
        self.user = create_user()
        create_password_history(self.user)
        super().setUp()

    def test_password_history_expiration_with_offset(self):
        """Test expiration of password history with an offset."""
        offset = settings.PASSWORD_HISTORY_COUNT + 2
        PasswordHistory.objects.delete_expired(self.user, offset=offset)
        count = PasswordHistory.objects.filter(user=self.user).count()
        self.assertEqual(count, offset)

    def test_password_history_expiration(self):
        """Test expiration of password history without an offset."""
        PasswordHistory.objects.delete_expired(self.user)
        count = PasswordHistory.objects.filter(user=self.user).count()
        self.assertEqual(count, settings.PASSWORD_HISTORY_COUNT)

    def test_password_history_recent_passwords(self):
        """Test checking recent passwords in password history."""
        self.assertFalse(PasswordHistory.objects.check_password(self.user, passwords[-1]))

