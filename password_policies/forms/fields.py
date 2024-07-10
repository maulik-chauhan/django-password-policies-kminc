from django import forms
from password_policies.forms.validators import (
    validate_common_sequences,
    validate_consecutive_count,
    validate_cracklib,
    validate_dictionary_words,
    validate_entropy,
    validate_letter_count,
    validate_lowercase_letter_count,
    validate_uppercase_letter_count,
    validate_number_count,
    validate_symbol_count,
    validate_not_email,
)


class PasswordPoliciesField(forms.CharField):
    """
    A form field that validates a password using various validators.
    """
    default_validators = [
        validate_common_sequences,
        validate_consecutive_count,
        validate_cracklib,
        validate_dictionary_words,
        validate_letter_count,
        validate_lowercase_letter_count,
        validate_uppercase_letter_count,
        validate_number_count,
        validate_symbol_count,
        validate_entropy,
        validate_not_email,
    ]

    def __init__(self, *args, **kwargs):
        if "widget" not in kwargs:
            kwargs["widget"] = forms.PasswordInput(render_value=False)
        super().__init__(*args, **kwargs)
