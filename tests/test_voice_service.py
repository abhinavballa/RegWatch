"""
Unit tests for the voice_service module.

Tests verify that the implementation conforms to the specification defined in
prompts/voice_service_Python.prompt. The prompt file is the source of truth.
"""

import json
import os
import sys
from typing import Iterator
from unittest.mock import Mock, MagicMock, patch, PropertyMock
import pytest
from requests.exceptions import RequestException, HTTPError, Timeout

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from voice_service import (
    narrate,
    generate_briefing,
    alert,
    _format_briefing_text,
    _get_headers,
    _make_request_with_retry,
    VoiceServiceError,
    AuthenticationError,
    RateLimitError,
    VOICE_ID_RACHEL,
    BASE_URL,
    VOICE_SETTINGS,
    OUTPUT_FORMAT,
    MODEL_ID
)


class TestConstants:
    """Tests for module-level constants."""

    def test_rachel_voice_id_is_correct(self):
        """Verify Rachel voice ID matches specification."""
        assert VOICE_ID_RACHEL == "21m00Tcm4TlvDq8ikWAM"

    def test_base_url_points_to_elevenlabs_api(self):
        """Verify base URL points to ElevenLabs text-to-speech endpoint."""
        assert BASE_URL == "https://api.elevenlabs.io/v1/text-to-speech"

    def test_output_format_is_mp3_44khz(self):
        """Verify output format is MP3 at 44.1kHz as per spec."""
        assert OUTPUT_FORMAT == "mp3_44100_128"

    def test_voice_settings_have_professional_tone(self):
        """Verify voice settings are configured for professional tone."""
        assert "stability" in VOICE_SETTINGS
        assert "similarity_boost" in VOICE_SETTINGS
        assert VOICE_SETTINGS["similarity_boost"] == 0.75


class TestGetHeaders:
    """Tests for _get_headers() function."""

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    def test_get_headers_with_api_key_set(self):
        """Verify headers include API key when environment variable is set."""
        headers = _get_headers()

        assert headers["xi-api-key"] == "test-api-key-123"
        assert headers["Content-Type"] == "application/json"

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    def test_get_headers_for_streaming_includes_accept_header(self):
        """Verify streaming requests include Accept header."""
        headers = _get_headers(stream=True)

        assert headers["Accept"] == "audio/mpeg"

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    def test_get_headers_for_batch_excludes_accept_header(self):
        """Verify batch requests don't include Accept header."""
        headers = _get_headers(stream=False)

        assert "Accept" not in headers

    @patch('voice_service.ELEVENLABS_API_KEY', None)
    def test_get_headers_raises_auth_error_when_api_key_missing(self):
        """Verify AuthenticationError is raised when API key is not set."""
        with pytest.raises(AuthenticationError) as exc_info:
            _get_headers()

        assert "ELEVENLABS_API_KEY environment variable is not set" in str(exc_info.value)


class TestMakeRequestWithRetry:
    """Tests for _make_request_with_retry() function."""

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_successful_request_returns_response(self, mock_post):
        """Verify successful API request returns response object."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        url = "https://api.test.com/endpoint"
        payload = {"text": "test"}

        result = _make_request_with_retry(url, payload)

        assert result == mock_response
        mock_post.assert_called_once()

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_401_error_raises_authentication_error(self, mock_post):
        """Verify 401 status code raises AuthenticationError."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        with pytest.raises(AuthenticationError) as exc_info:
            _make_request_with_retry("https://api.test.com", {})

        assert "Invalid ElevenLabs API Key" in str(exc_info.value)

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_429_error_raises_rate_limit_error(self, mock_post):
        """Verify 429 status code raises RateLimitError."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_post.return_value = mock_response

        with pytest.raises(RateLimitError) as exc_info:
            _make_request_with_retry("https://api.test.com", {})

        assert "rate limit exceeded" in str(exc_info.value)

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    @patch('voice_service.time.sleep')
    def test_retry_logic_with_exponential_backoff(self, mock_sleep, mock_post):
        """Verify retry logic uses exponential backoff (1s, 2s, 4s)."""
        # Simulate 3 failures then success
        mock_response_fail = Mock()
        mock_response_fail.status_code = 500
        mock_response_fail.raise_for_status.side_effect = HTTPError()

        mock_response_success = Mock()
        mock_response_success.status_code = 200

        mock_post.side_effect = [
            HTTPError(),
            HTTPError(),
            HTTPError(),
            mock_response_success
        ]

        result = _make_request_with_retry("https://api.test.com", {})

        # Verify exponential backoff: 1s, 2s, 4s
        assert mock_sleep.call_count == 3
        sleep_times = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_times == [1, 2, 4]

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    @patch('voice_service.time.sleep')
    def test_max_retries_exceeded_raises_voice_service_error(self, mock_sleep, mock_post):
        """Verify VoiceServiceError is raised after max retries."""
        mock_post.side_effect = HTTPError("Connection failed")

        with pytest.raises(VoiceServiceError) as exc_info:
            _make_request_with_retry("https://api.test.com", {}, max_retries=3)

        assert "Failed to generate audio after retries" in str(exc_info.value)
        # 3 retries = 4 total attempts
        assert mock_post.call_count == 4

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_auth_error_is_not_retried(self, mock_post):
        """Verify authentication errors are not retried."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        with pytest.raises(AuthenticationError):
            _make_request_with_retry("https://api.test.com", {})

        # Should only be called once, not retried
        assert mock_post.call_count == 1

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_streaming_request_uses_correct_timeout(self, mock_post):
        """Verify streaming requests use (5, 30) timeout."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        _make_request_with_retry("https://api.test.com", {}, stream=True)

        # Check that timeout parameter was (5, 30) for streaming
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs['timeout'] == (5, 30)
        assert call_kwargs['stream'] is True

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_batch_request_uses_correct_timeout(self, mock_post):
        """Verify batch requests use 30 second timeout."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        _make_request_with_retry("https://api.test.com", {}, stream=False)

        # Check that timeout parameter was 30 for batch
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs['timeout'] == 30
        assert call_kwargs['stream'] is False


class TestNarrate:
    """Tests for narrate() function."""

    @patch('voice_service._make_request_with_retry')
    def test_narrate_batch_mode_returns_bytes(self, mock_request):
        """Verify narrate in batch mode returns complete audio bytes."""
        mock_response = Mock()
        mock_response.content = b"fake-mp3-audio-data"
        mock_request.return_value = mock_response

        result = narrate("Hello world", stream=False)

        assert isinstance(result, bytes)
        assert result == b"fake-mp3-audio-data"

    @patch('voice_service._make_request_with_retry')
    def test_narrate_streaming_mode_returns_iterator(self, mock_request):
        """Verify narrate in streaming mode returns Iterator[bytes]."""
        mock_response = Mock()
        mock_response.iter_content = Mock(return_value=[b"chunk1", b"chunk2", b"chunk3"])
        mock_response.close = Mock()
        mock_request.return_value = mock_response

        result = narrate("Hello world", stream=True)

        # Verify it's an iterator/generator
        assert hasattr(result, '__iter__')
        assert hasattr(result, '__next__')

        # Consume the iterator
        chunks = list(result)
        assert chunks == [b"chunk1", b"chunk2", b"chunk3"]

        # Verify cleanup was called
        mock_response.close.assert_called_once()

    @patch('voice_service._make_request_with_retry')
    def test_narrate_uses_rachel_voice_id(self, mock_request):
        """Verify narrate uses Rachel voice ID in URL."""
        mock_response = Mock()
        mock_response.content = b"audio"
        mock_request.return_value = mock_response

        narrate("Test", stream=False)

        # Check the URL includes Rachel's voice ID
        called_url = mock_request.call_args[0][0]
        assert VOICE_ID_RACHEL in called_url

    @patch('voice_service._make_request_with_retry')
    def test_narrate_batch_url_format(self, mock_request):
        """Verify batch mode URL format is correct."""
        mock_response = Mock()
        mock_response.content = b"audio"
        mock_request.return_value = mock_response

        narrate("Test", stream=False)

        called_url = mock_request.call_args[0][0]
        assert f"{BASE_URL}/{VOICE_ID_RACHEL}" in called_url
        assert "optimize_streaming_latency=0" in called_url
        assert f"output_format={OUTPUT_FORMAT}" in called_url

    @patch('voice_service._make_request_with_retry')
    def test_narrate_streaming_url_includes_stream_endpoint(self, mock_request):
        """Verify streaming mode URL includes /stream endpoint."""
        mock_response = Mock()
        mock_response.iter_content = Mock(return_value=[b"chunk"])
        mock_response.close = Mock()
        mock_request.return_value = mock_response

        result = narrate("Test", stream=True)
        list(result)  # Consume iterator

        called_url = mock_request.call_args[0][0]
        assert "/stream" in called_url
        assert "optimize_streaming_latency=3" in called_url

    @patch('voice_service._make_request_with_retry')
    def test_narrate_includes_voice_settings_in_payload(self, mock_request):
        """Verify narrate includes professional voice settings in request."""
        mock_response = Mock()
        mock_response.content = b"audio"
        mock_request.return_value = mock_response

        narrate("Test", stream=False)

        payload = mock_request.call_args[0][1]
        assert payload["voice_settings"] == VOICE_SETTINGS
        assert payload["model_id"] == MODEL_ID
        assert payload["text"] == "Test"

    def test_narrate_empty_text_returns_empty_bytes(self):
        """Verify narrate handles empty text by returning empty bytes."""
        result = narrate("", stream=False)
        assert result == b""

    def test_narrate_whitespace_only_returns_empty_bytes(self):
        """Verify narrate handles whitespace-only text by returning empty bytes."""
        result = narrate("   \n\t  ", stream=False)
        assert result == b""

    def test_narrate_empty_text_streaming_returns_empty_iterator(self):
        """Verify narrate handles empty text in streaming mode."""
        result = narrate("", stream=True)
        chunks = list(result)
        assert chunks == []

    @patch('voice_service._make_request_with_retry')
    def test_narrate_raises_voice_service_error_on_failure(self, mock_request):
        """Verify narrate re-raises VoiceServiceError on API failure."""
        mock_request.side_effect = VoiceServiceError("API failure")

        with pytest.raises(VoiceServiceError):
            narrate("Test", stream=False)

    @patch('voice_service._make_request_with_retry')
    def test_narrate_streaming_filters_empty_chunks(self, mock_request):
        """Verify streaming mode filters out empty chunks."""
        mock_response = Mock()
        # Include empty chunks that should be filtered
        mock_response.iter_content = Mock(return_value=[b"chunk1", b"", b"chunk2", None, b"chunk3"])
        mock_response.close = Mock()
        mock_request.return_value = mock_response

        result = narrate("Test", stream=True)
        chunks = list(result)

        # Empty chunks should be filtered out
        assert chunks == [b"chunk1", b"chunk2", b"chunk3"]


class TestFormatBriefingText:
    """Tests for _format_briefing_text() function."""

    def test_format_briefing_includes_compliance_score(self):
        """Verify briefing includes compliance score."""
        scan_results = {
            "compliance_score": "85%",
            "total_violations": 10,
            "severity_breakdown": {},
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "compliance scan resulted in a score of 85%" in script

    def test_format_briefing_includes_total_violations(self):
        """Verify briefing includes total violation count."""
        scan_results = {
            "compliance_score": "90%",
            "total_violations": 42,
            "severity_breakdown": {},
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "total of 42 violations" in script

    def test_format_briefing_includes_severity_breakdown_critical(self):
        """Verify briefing includes critical severity count."""
        scan_results = {
            "compliance_score": "70%",
            "total_violations": 5,
            "severity_breakdown": {
                "critical": 3,
                "high": 2,
                "medium": 0,
                "low": 0
            },
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "3 critical issues" in script

    def test_format_briefing_includes_severity_breakdown_high(self):
        """Verify briefing includes high severity count."""
        scan_results = {
            "compliance_score": "75%",
            "total_violations": 8,
            "severity_breakdown": {
                "critical": 0,
                "high": 5,
                "medium": 3,
                "low": 0
            },
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "5 high priority issues" in script

    def test_format_briefing_mentions_medium_low_when_no_critical_high(self):
        """Verify briefing mentions medium/low when no critical or high issues."""
        scan_results = {
            "compliance_score": "95%",
            "total_violations": 5,
            "severity_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 3,
                "low": 2
            },
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "mostly medium to low priority findings" in script

    def test_format_briefing_includes_top_issues(self):
        """Verify briefing includes top issues descriptions."""
        scan_results = {
            "compliance_score": "80%",
            "total_violations": 10,
            "severity_breakdown": {},
            "top_issues": [
                {"description": "Unencrypted database connection"},
                {"description": "Missing access control on endpoint"},
                {"description": "Weak password policy"}
            ]
        }

        script = _format_briefing_text(scan_results)

        assert "Number 1: Unencrypted database connection" in script
        assert "Number 2: Missing access control on endpoint" in script
        assert "Number 3: Weak password policy" in script

    def test_format_briefing_limits_top_issues_to_three(self):
        """Verify briefing only includes top 3 issues."""
        scan_results = {
            "compliance_score": "80%",
            "total_violations": 10,
            "severity_breakdown": {},
            "top_issues": [
                {"description": "Issue 1"},
                {"description": "Issue 2"},
                {"description": "Issue 3"},
                {"description": "Issue 4"},
                {"description": "Issue 5"}
            ]
        }

        script = _format_briefing_text(scan_results)

        assert "Number 1: Issue 1" in script
        assert "Number 2: Issue 2" in script
        assert "Number 3: Issue 3" in script
        assert "Issue 4" not in script
        assert "Issue 5" not in script

    def test_format_briefing_handles_missing_issue_description(self):
        """Verify briefing handles issues without description field."""
        scan_results = {
            "compliance_score": "80%",
            "total_violations": 1,
            "severity_breakdown": {},
            "top_issues": [
                {"type": "security"},  # Missing description
            ]
        }

        script = _format_briefing_text(scan_results)

        assert "Unknown issue" in script

    def test_format_briefing_includes_outro(self):
        """Verify briefing includes call to action outro."""
        scan_results = {
            "compliance_score": "90%",
            "total_violations": 0,
            "severity_breakdown": {},
            "top_issues": []
        }

        script = _format_briefing_text(scan_results)

        assert "review the full report in the dashboard" in script

    def test_format_briefing_handles_missing_fields_gracefully(self):
        """Verify briefing handles missing fields with defaults."""
        scan_results = {}

        script = _format_briefing_text(scan_results)

        assert "compliance scan resulted in a score of unknown" in script
        assert "total of 0 violations" in script

    def test_format_briefing_natural_language_flow(self):
        """Verify briefing reads as natural language."""
        scan_results = {
            "compliance_score": "75%",
            "total_violations": 15,
            "severity_breakdown": {
                "critical": 2,
                "high": 5,
                "medium": 8,
                "low": 0
            },
            "top_issues": [
                {"description": "SQL injection vulnerability"}
            ]
        }

        script = _format_briefing_text(scan_results)

        # Should start with intro
        assert script.startswith("Here is your RegWatch executive briefing")
        # Should have proper sentence structure
        assert ". " in script  # Sentences end with period and space
        # Should not have awkward formatting
        assert "  " not in script  # No double spaces


class TestGenerateBriefing:
    """Tests for generate_briefing() function."""

    @patch('voice_service.narrate')
    def test_generate_briefing_returns_bytes(self, mock_narrate):
        """Verify generate_briefing returns MP3 audio bytes."""
        mock_narrate.return_value = b"briefing-audio-data"

        scan_results = {
            "compliance_score": "90%",
            "total_violations": 5,
            "severity_breakdown": {},
            "top_issues": []
        }

        result = generate_briefing(scan_results)

        assert isinstance(result, bytes)
        assert result == b"briefing-audio-data"

    @patch('voice_service.narrate')
    def test_generate_briefing_calls_narrate_in_batch_mode(self, mock_narrate):
        """Verify generate_briefing uses batch mode (stream=False)."""
        mock_narrate.return_value = b"audio"

        scan_results = {"compliance_score": "90%"}
        generate_briefing(scan_results)

        mock_narrate.assert_called_once()
        call_kwargs = mock_narrate.call_args[1]
        assert call_kwargs['stream'] is False

    @patch('voice_service.narrate')
    def test_generate_briefing_formats_scan_results(self, mock_narrate):
        """Verify generate_briefing formats scan results into script."""
        mock_narrate.return_value = b"audio"

        scan_results = {
            "compliance_score": "85%",
            "total_violations": 10,
            "severity_breakdown": {"critical": 2},
            "top_issues": [{"description": "Security issue"}]
        }

        generate_briefing(scan_results)

        # Verify the text passed to narrate contains formatted content
        called_text = mock_narrate.call_args[0][0]
        assert "85%" in called_text
        assert "10 violations" in called_text

    @patch('voice_service.narrate')
    def test_generate_briefing_truncates_long_scripts(self, mock_narrate):
        """Verify briefing truncates scripts longer than 4500 characters."""
        mock_narrate.return_value = b"audio"

        # Create scan results with many issues to generate long script
        scan_results = {
            "compliance_score": "50%",
            "total_violations": 1000,
            "severity_breakdown": {"critical": 500, "high": 500},
            "top_issues": [
                {"description": "Very long description " * 100} for _ in range(50)
            ]
        }

        generate_briefing(scan_results)

        called_text = mock_narrate.call_args[0][0]
        # Should be truncated to under 5000 chars
        assert len(called_text) < 5000
        # Should include truncation message
        if len(_format_briefing_text(scan_results)) > 4500:
            assert "See full report for details" in called_text


class TestAlert:
    """Tests for alert() function."""

    @patch('voice_service.narrate')
    def test_alert_returns_bytes(self, mock_narrate):
        """Verify alert returns MP3 audio bytes."""
        mock_narrate.return_value = b"alert-audio-data"

        result = alert("Critical security breach detected")

        assert isinstance(result, bytes)
        assert result == b"alert-audio-data"

    @patch('voice_service.narrate')
    def test_alert_calls_narrate_in_batch_mode(self, mock_narrate):
        """Verify alert uses batch mode (stream=False)."""
        mock_narrate.return_value = b"audio"

        alert("Test alert")

        mock_narrate.assert_called_once()
        call_kwargs = mock_narrate.call_args[1]
        assert call_kwargs['stream'] is False

    @patch('voice_service.narrate')
    def test_alert_prepends_attention_marker(self, mock_narrate):
        """Verify alert prepends 'Attention. RegWatch Alert.' to message."""
        mock_narrate.return_value = b"audio"

        message = "Database connection lost"
        alert(message)

        called_text = mock_narrate.call_args[0][0]
        assert called_text.startswith("Attention. RegWatch Alert.")
        assert message in called_text

    @patch('voice_service.narrate')
    def test_alert_includes_original_message(self, mock_narrate):
        """Verify alert includes the original message text."""
        mock_narrate.return_value = b"audio"

        message = "High CPU usage detected"
        alert(message)

        called_text = mock_narrate.call_args[0][0]
        assert message in called_text

    @patch('voice_service.narrate')
    def test_alert_format_creates_urgent_tone(self, mock_narrate):
        """Verify alert format is designed for urgency."""
        mock_narrate.return_value = b"audio"

        alert("System failure")

        called_text = mock_narrate.call_args[0][0]
        # Should have attention markers
        assert "Attention" in called_text
        assert "Alert" in called_text


class TestExceptionHierarchy:
    """Tests for custom exception classes."""

    def test_voice_service_error_is_base_exception(self):
        """Verify VoiceServiceError is the base exception class."""
        assert issubclass(VoiceServiceError, Exception)

    def test_authentication_error_inherits_from_voice_service_error(self):
        """Verify AuthenticationError inherits from VoiceServiceError."""
        assert issubclass(AuthenticationError, VoiceServiceError)

    def test_rate_limit_error_inherits_from_voice_service_error(self):
        """Verify RateLimitError inherits from VoiceServiceError."""
        assert issubclass(RateLimitError, VoiceServiceError)

    def test_exceptions_can_be_raised_with_message(self):
        """Verify exceptions can be instantiated with messages."""
        try:
            raise VoiceServiceError("Test error message")
        except VoiceServiceError as e:
            assert str(e) == "Test error message"


class TestIntegration:
    """Integration tests for complete workflows."""

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_complete_narration_workflow_batch(self, mock_post):
        """Test complete batch narration workflow from start to finish."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"complete-audio-file"
        mock_post.return_value = mock_response

        result = narrate("This is a compliance violation alert", stream=False)

        assert result == b"complete-audio-file"

        # Verify correct API call was made
        assert mock_post.called
        call_args = mock_post.call_args
        url = call_args[0][0]
        payload = call_args[1]['json']

        assert VOICE_ID_RACHEL in url
        assert payload['text'] == "This is a compliance violation alert"
        assert payload['voice_settings'] == VOICE_SETTINGS

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_complete_briefing_workflow(self, mock_post):
        """Test complete briefing generation workflow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"briefing-audio"
        mock_post.return_value = mock_response

        scan_results = {
            "compliance_score": "88%",
            "total_violations": 7,
            "severity_breakdown": {
                "critical": 1,
                "high": 3,
                "medium": 3,
                "low": 0
            },
            "top_issues": [
                {"description": "Unencrypted data transmission"},
                {"description": "Weak authentication mechanism"}
            ]
        }

        result = generate_briefing(scan_results)

        assert result == b"briefing-audio"

        # Verify the script was properly formatted
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        script = payload['text']

        assert "88%" in script
        assert "7 violations" in script
        assert "1 critical issue" in script
        assert "3 high priority issues" in script
        assert "Unencrypted data transmission" in script

    @patch('voice_service.ELEVENLABS_API_KEY', 'test-api-key-123')
    @patch('voice_service.requests.post')
    def test_complete_alert_workflow(self, mock_post):
        """Test complete alert generation workflow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"alert-audio"
        mock_post.return_value = mock_response

        result = alert("New critical vulnerability detected in production")

        assert result == b"alert-audio"

        # Verify alert formatting
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        text = payload['text']

        assert text.startswith("Attention. RegWatch Alert.")
        assert "New critical vulnerability detected in production" in text
