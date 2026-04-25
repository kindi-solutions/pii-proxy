"""Presidio-based PII sanitizer for Anthropic API request bodies."""

from __future__ import annotations

import logging
from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .audit_log import log_pii_detection
from .config import Settings
from .message_walker import sanitize_request_body
from .secret_key_recognizers import get_secret_key_recognizers
from .swedish_recognizers import get_swedish_recognizers

logger = logging.getLogger(__name__)


class Sanitizer:
    """Orchestrates Presidio analysis and anonymization of API requests."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.anonymizer = AnonymizerEngine()

        # Load heavy NLP models only when NER entities (PERSON, LOCATION) are configured
        _NER_ENTITIES = {"PERSON", "LOCATION", "ORGANIZATION"}
        needs_ner = bool(_NER_ENTITIES & set(settings.sanitization.entities))

        from presidio_analyzer.nlp_engine import SpacyNlpEngine
        if needs_ner:
            nlp_models = [{"lang_code": "en", "model_name": "en_core_web_lg"}]
            try:
                import spacy
                spacy.load("sv_core_news_lg")
                nlp_models.append({"lang_code": "sv", "model_name": "sv_core_news_lg"})
                logger.info("Swedish spaCy model loaded for NER")
            except Exception:
                logger.warning("Swedish spaCy model not available; Swedish NER will be limited to pattern-based detection")
            logger.info("NER enabled — loading large spaCy models")
        else:
            nlp_models = [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            logger.info("PERSON/LOCATION not configured — using lightweight model (pattern-only mode)")

        nlp_engine = SpacyNlpEngine(models=nlp_models)
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Register custom recognizers
        registry = self.analyzer.registry
        for recognizer in get_swedish_recognizers() + get_secret_key_recognizers():
            registry.add_recognizer(recognizer)
            logger.info("Registered recognizer: %s", recognizer.supported_entities)

        self._entity_counters: dict[str, int] = {}

    def _reset_counters(self) -> None:
        """Reset placeholder counters for a new request."""
        self._entity_counters = {}

    def _get_placeholder(self, entity_type: str) -> str:
        """Generate a deterministic placeholder like <PERSON_1>."""
        count = self._entity_counters.get(entity_type, 0) + 1
        self._entity_counters[entity_type] = count
        return f"<{entity_type}_{count}>"

    def _merge_results(self, *result_lists: list[RecognizerResult]) -> list[RecognizerResult]:
        """Merge and deduplicate overlapping recognizer results, keeping highest score."""
        all_results: list[RecognizerResult] = []
        for results in result_lists:
            all_results.extend(results)

        if not all_results:
            return []

        # Sort by start position, then by score descending
        all_results.sort(key=lambda r: (r.start, -r.score))

        merged: list[RecognizerResult] = []
        for result in all_results:
            if result.score < self.settings.sanitization.score_threshold:
                continue

            # Check for overlap with already-accepted results
            overlaps = False
            for accepted in merged:
                if result.start < accepted.end and result.end > accepted.start:
                    overlaps = True
                    break
            if not overlaps:
                merged.append(result)

        return merged

    def sanitize_text(self, text: str) -> str:
        """Analyze and anonymize PII in a text string."""
        if not text or not text.strip():
            return text

        # Run analysis in configured languages
        all_results: list[list[RecognizerResult]] = []
        for lang in self.settings.sanitization.languages:
            try:
                # Only pass entities that have recognizers in this language
                results = self.analyzer.analyze(
                    text=text,
                    language=lang,
                    allow_list=self.settings.allowlist,
                )
                # Filter to configured entities
                configured = set(self.settings.sanitization.entities)
                results = [r for r in results if r.entity_type in configured]
                all_results.append(results)
            except Exception:
                # Language model might not be available
                pass

        merged = self._merge_results(*all_results)

        if not merged:
            return text

        # Build operator config with deterministic placeholders
        # Track unique values to reuse same placeholder for same PII
        value_to_placeholder: dict[str, str] = {}
        operators: dict[str, OperatorConfig] = {}

        for result in merged:
            original_value = text[result.start : result.end]
            if original_value in value_to_placeholder:
                placeholder = value_to_placeholder[original_value]
            else:
                placeholder = self._get_placeholder(result.entity_type)
                value_to_placeholder[original_value] = placeholder

            # Presidio requires per-entity-type operators, but we want per-result
            # So we use a unique entity type key
            operators[result.entity_type] = OperatorConfig("replace", {"new_value": placeholder})

        # Log PII detections
        log_pii_detection(
            merged,
            text if self.settings.audit.log_original_values else None,
            self.settings.audit,
        )

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=merged,
            operators=operators,
        )

        logger.debug("Sanitized %d PII entities", len(merged))
        return anonymized.text

    def sanitize_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """Sanitize all text fields in an Anthropic Messages API request body."""
        self._reset_counters()
        return sanitize_request_body(body, self.sanitize_text)
