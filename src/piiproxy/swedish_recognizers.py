"""Custom Presidio recognizers for Swedish PII types."""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


def _luhn_checksum(digits: str) -> bool:
    """Validate a string of digits using the Luhn algorithm."""
    nums = [int(d) for d in digits]
    checksum = 0
    for i, n in enumerate(nums):
        if i % 2 == 0:
            doubled = n * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += n
    return checksum % 10 == 0


def _validate_personnummer_date(year: int, month: int, day: int) -> bool:
    """Check if year/month/day form a plausible date."""
    if month < 1 or month > 12:
        return False
    if day < 1 or day > 31:
        return False
    return True


class SwedishPersonnummerRecognizer(PatternRecognizer):
    """Recognizes Swedish personnummer (personal identity numbers).

    Formats: YYYYMMDD-XXXX, YYYYMMDDXXXX, YYMMDD-XXXX, YYMMDDXXXX
    The + separator indicates age 100+.
    """

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "personnummer_12",
            r"\b(\d{8}[-+]?\d{4})\b",
            0.7,
        ),
        Pattern(
            "personnummer_10",
            r"\b(\d{6}[-+]?\d{4})\b",
            0.6,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="SE_PERSONNUMMER",
            patterns=self.PATTERNS,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        """Validate with date check; Luhn failure is inconclusive, not rejection."""
        cleaned = re.sub(r"[-+]", "", pattern_text)

        if len(cleaned) == 12:
            year = int(cleaned[0:4])
            month = int(cleaned[4:6])
            day = int(cleaned[6:8])
            luhn_digits = cleaned[2:]
        elif len(cleaned) == 10:
            year = int(cleaned[0:2])
            month = int(cleaned[2:4])
            day = int(cleaned[4:6])
            luhn_digits = cleaned
        else:
            return False

        if not _validate_personnummer_date(year if year > 99 else 1900 + year, month, day):
            return False

        # Luhn pass → high confidence; fail → inconclusive (keep pattern score)
        return True if _luhn_checksum(luhn_digits) else None


class SwedishSamordningsnummerRecognizer(PatternRecognizer):
    """Recognizes Swedish samordningsnummer (coordination numbers).

    Same format as personnummer but day field is increased by 60.
    """

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "samordningsnummer_12",
            r"\b(\d{8}[-+]?\d{4})\b",
            0.6,
        ),
        Pattern(
            "samordningsnummer_10",
            r"\b(\d{6}[-+]?\d{4})\b",
            0.5,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="SE_SAMORDNINGSNUMMER",
            patterns=self.PATTERNS,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate: day field must be 61-91, plus Luhn checksum."""
        cleaned = re.sub(r"[-+]", "", pattern_text)

        if len(cleaned) == 12:
            day = int(cleaned[6:8])
            luhn_digits = cleaned[2:]
        elif len(cleaned) == 10:
            day = int(cleaned[4:6])
            luhn_digits = cleaned
        else:
            return False

        # Coordination numbers have day + 60
        if day < 61 or day > 91:
            return False

        return _luhn_checksum(luhn_digits)


class SwedishOrganizationNumberRecognizer(PatternRecognizer):
    """Recognizes Swedish organisationsnummer.

    Format: NNNNNN-NNNN where the 3rd digit >= 2 (distinguishes from personnummer).
    """

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "org_number",
            r"\b(\d{6}-?\d{4})\b",
            0.6,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="SE_ORGANIZATION_NUMBER",
            patterns=self.PATTERNS,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """3rd digit must be >= 2, plus Luhn checksum."""
        cleaned = pattern_text.replace("-", "")
        if len(cleaned) != 10:
            return False

        # 3rd digit >= 2 distinguishes org from person
        if int(cleaned[2]) < 2:
            return False

        return _luhn_checksum(cleaned)


class SwedishPostalCodeRecognizer(PatternRecognizer):
    """Recognizes Swedish postal codes (postnummer).

    Format: NNN NN or NNNNN, typically preceded by SE- or followed by a city name.
    """

    CONTEXT_WORDS: ClassVar[list[str]] = [
        "gatan", "gata", "vägen", "väg", "plats", "torg",
        "stockholm", "göteborg", "malmö", "uppsala", "linköping",
        "postnummer", "postkod", "adress",
    ]

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "postal_code_spaced",
            r"\b(\d{3}\s\d{2})\b",
            0.4,
        ),
        Pattern(
            "postal_code_compact",
            r"\b(\d{5})\b",
            0.2,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="SE_POSTAL_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language="en",
        )


def get_swedish_recognizers() -> list[PatternRecognizer]:
    """Return all custom Swedish PII recognizers."""
    return [
        SwedishPersonnummerRecognizer(),
        SwedishSamordningsnummerRecognizer(),
        SwedishOrganizationNumberRecognizer(),
        SwedishPostalCodeRecognizer(),
    ]
