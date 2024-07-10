import itertools
import math
import re
import unicodedata

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from password_policies.conf import settings

try:
    from django.utils.encoding import force_text
except ImportError:
    from django.utils.encoding import smart_str as force_text


class BaseCountValidator:
    """
    Base class for counting character occurrences and raising ValidationError if requirements are not met.
    """

    def __call__(self, value):
        if not self.get_min_count():
            return

        counter = sum(1 for character in force_text(value) if self._is_valid_character(character))

        if counter < self.get_min_count():
            raise ValidationError(self.get_error_message(), code=self.code)

    def _is_valid_character(self, character):
        raise NotImplementedError

    def get_error_message(self):
        raise NotImplementedError

    def get_min_count(self):
        raise NotImplementedError


class BaseRFC4013Validator:
    """
    Base class for validating passwords against RFC 4013 requirements.
    """

    def __call__(self, value):
        value = force_text(value)
        self._process(value)

    def _process(self, value):
        raise NotImplementedError


class BaseSimilarityValidator:
    """
    Base class for comparing passwords against a list of common sequences.
    """

    def __init__(self, haystacks=None):
        self.haystacks = haystacks or []

    def __call__(self, value):
        needle = force_text(value)
        for haystack in self.haystacks:
            similarity = self._calculate_similarity(needle, haystack)
            if similarity >= self.get_threshold():
                raise ValidationError(
                    self.message % {"haystacks": ", ".join(self.haystacks)},
                    code=self.code,
                )

    def _calculate_similarity(self, needle, haystack):
        raise NotImplementedError

    def get_threshold(self):
        raise NotImplementedError


class BidirectionalValidator(BaseRFC4013Validator):
    """
    Validates that a password does not contain ambiguous bidirectional characters.
    """
    code = "invalid_bidirectional"
    message = _("The new password contains ambiguous bidirectional characters.")

    def _process(self, value):
        for code in force_text(value):
            if self._is_valid_code(code):
                raise ValidationError(self.message, code=self.code)

    def _is_valid_code(self, code):
        raise NotImplementedError


class CommonSequenceValidator(BaseSimilarityValidator):
    """
    Validates that a password is not based on a common sequence of characters.
    """
    code = "invalid_common_sequence"
    message = _("The new password is based on a common sequence of characters.")

    def _calculate_similarity(self, needle, haystack):
        needle, haystack = needle.lower(), haystack.lower()
        return self._fuzzy_substring(needle, haystack)

    def _fuzzy_substring(self, needle, haystack):
        m, n = len(needle), len(haystack)

        if m == 1:
            return -1 if needle not in haystack else 0
        if not n:
            return m

        previous_row = range(n + 1)
        for i, needle_character in enumerate(needle):
            current_row = [i + 1]
            for j, haystack_character in enumerate(haystack):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (needle_character != haystack_character)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return min(previous_row)

    def get_threshold(self):
        return settings.PASSWORD_MATCH_THRESHOLD


class ConsecutiveCountValidator:
    """
    Validates that a password does not contain consecutive characters.
    """
    code = "invalid_consecutive_count"

    def __call__(self, value):
        if not self.get_max_count():
            return

        for group_key, group_iterator in itertools.groupby(force_text(value)):
            group = list(group_iterator)
            if len(group) > self.get_max_count():
                raise ValidationError(self.get_error_message(len(group)), code=self.code)

    def get_max_count(self):
        return settings.PASSWORD_MAX_CONSECUTIVE

    def get_error_message(self, count):
        return _(
            "The new password contains consecutive characters. Only %(count)d consecutive character is allowed.") % {
            "count": count}


class CracklibValidator:
    """
    Validates a password using Python bindings for cracklib.
    """
    code = "invalid_cracklib"

    def __call__(self, value):
        if not settings.PASSWORD_USE_CRACKLIB:
            return

        try:
            import crack
        except ImportError:
            return

        try:
            self._run_cracklib(value)
        except ValueError as ex:
            message = _("Please choose a different password, %(reason)s.") % {"reason": ex}
            raise ValidationError(message, code=self.code)

    def _run_cracklib(self, value):
        import crack

        crack.diff_ok = self.diff_ok
        crack.dig_credit = self.dig_credit
        crack.low_credit = self.low_credit
        crack.min_length = self.min_length
        crack.oth_credit = self.oth_credit
        crack.up_credit = self.up_credit

        crack.FascistCheck(value)

    def __init__(self, diff_ok=0, dig_credit=0, low_credit=0, min_length=6, oth_credit=0, up_credit=0):
        self.diff_ok = diff_ok
        self.dig_credit = dig_credit
        self.low_credit = low_credit
        self.min_length = min_length
        self.oth_credit = oth_credit
        self.up_credit = up_credit


class EntropyValidator:
    """
    Validates that a password contains varied characters by calculating the Shannon entropy.
    """
    code = "invalid_entropy"
    message = _("The new password is not varied enough.")

    def __call__(self, value):
        pw_length = len(value)
        if pw_length < 100 and not self.short_min_entropy:
            return
        if pw_length >= 100 and not self.long_min_entropy:
            return

        entropy = self._calculate_entropy(value)
        ideal_entropy = self._calculate_ideal_entropy(pw_length)
        entropy_quotient = entropy / ideal_entropy if ideal_entropy else 0

        if (pw_length < 100 and entropy_quotient < self.short_min_entropy) or (
            pw_length >= 100 and entropy < self.long_min_entropy):
            raise ValidationError(self.message, code=self.code)

    def _calculate_entropy(self, value):
        prob = [float(value.count(c)) / len(value) for c in dict.fromkeys(list(value))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def _calculate_ideal_entropy(self, length):
        prob = 1.0 / length
        return -1.0 * length * prob * math.log(prob) / math.log(2.0)


class DictionaryValidator(BaseSimilarityValidator):
    """
    Validates that a password is not based on a dictionary word.
    """
    code = "invalid_dictionary_word"
    message = _("The new password is based on a dictionary word.")

    def __init__(self, dictionary=None, words=None):
        self.dictionary = dictionary or settings.PASSWORD_DICTIONARY
        self.words = words or settings.PASSWORD_WORDS

        haystacks = []
        if self.dictionary:
            with open(self.dictionary) as f:
                haystacks.extend(smart_text(x.strip()) for x in f.readlines())
        if self.words:
            haystacks.extend(self.words)

        super().__init__(haystacks=haystacks)

    def _calculate_similarity(self, needle, haystack):
        return self._fuzzy_substring(needle.lower(), haystack.lower())

    def _fuzzy_substring(self, needle, haystack):
        m, n = len(needle), len(haystack)
        if m == 1:
            return -1 if needle not in haystack else 0
        if not n:
            return m

        previous_row = range(n + 1)
        for i, needle_character in enumerate(needle):
            current_row = [i + 1]
            for j, haystack_character in enumerate(haystack):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (needle_character != haystack_character)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return min(previous_row)


class InvalidCharacterValidator(BaseRFC4013Validator):
    """
    Validates that a password does not contain invalid unicode characters.
    """
    code = "invalid_unicode"
    message = _("The new password contains invalid unicode characters.")

    def _process(self, value):
        for code in force_text(value):
            if self._is_invalid_code(code):
                raise ValidationError(self.message, code=self.code)

    def _is_invalid_code(self, code):
        raise NotImplementedError


class LetterCountValidator(BaseCountValidator):
    """
    Validates that a password contains a minimum number of letters.
    """
    code = "invalid_letter_count"
    categories = ["LC", "Ll", "Lu", "Lt", "Lo", "Nl"]

    def _is_valid_character(self, character):
        return unicodedata.category(character) in self.categories

    def get_error_message(self):
        return _("The new password must contain %(count)d or more letters.") % {"count": self.get_min_count()}

    def get_min_count(self):
        return settings.PASSWORD_MIN_LETTERS


class LengthValidator(BaseRFC4013Validator):
    """
    Validates that a password meets length requirements.
    """
    code = "invalid_length"
    message = _("The new password must be at least %(min_length)d characters long.")

    def _process(self, value):
        if len(force_text(value)) < self.get_min_length():
            raise ValidationError(self.message % {"min_length": self.get_min_length()}, code=self.code)

    def get_min_length(self):
        return settings.PASSWORD_MIN_LENGTH


class NumberCountValidator(BaseCountValidator):
    """
    Validates that a password contains a minimum number of numeric digits.
    """
    code = "invalid_number_count"
    categories = ["Nd"]

    def _is_valid_character(self, character):
        return unicodedata.category(character) in self.categories

    def get_error_message(self):
        return _("The new password must contain %(count)d or more numeric digits.") % {"count": self.get_min_count()}

    def get_min_count(self):
        return settings.PASSWORD_MIN_NUMBERS


class SymbolCountValidator(BaseCountValidator):
    """
    Validates that a password contains a minimum number of symbols.
    """
    code = "invalid_symbol_count"
    categories = ["Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc", "Sk", "So"]

    def _is_valid_character(self, character):
        return unicodedata.category(character) in self.categories

    def get_error_message(self):
        return _("The new password must contain %(count)d or more symbols.") % {"count": self.get_min_count()}

    def get_min_count(self):
        return settings.PASSWORD_MIN_SYMBOLS


class UppercaseCountValidator(BaseCountValidator):
    """
    Validates that a password contains a minimum number of uppercase letters.
    """
    code = "invalid_uppercase_count"
    categories = ["Lu"]

    def _is_valid_character(self, character):
        return unicodedata.category(character) in self.categories

    def get_error_message(self):
        return _("The new password must contain %(count)d or more uppercase letters.") % {"count": self.get_min_count()}

    def get_min_count(self):
        return settings.PASSWORD_MIN_UPPERCASE


class UsernameValidator(BaseSimilarityValidator):
    """
    Validates that a password is not similar to the username.
    """
    code = "invalid_username"
    message = _("The new password is too similar to the username.")

    def __init__(self, username=None):
        self.username = username or ""

    def __call__(self, value):
        needle = force_text(value)
        if self._calculate_similarity(needle, self.username) >= self.get_threshold():
            raise ValidationError(self.message, code=self.code)

    def _calculate_similarity(self, needle, haystack):
        needle, haystack = needle.lower(), haystack.lower()
        return self._fuzzy_substring(needle, haystack)

    def get_threshold(self):
        return settings.PASSWORD_MATCH_THRESHOLD
