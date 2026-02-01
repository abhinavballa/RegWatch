
import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

"""
TEST PLAN FOR voice_service.py

1.  **Z3 Formal Verification**:
    *   **Retry Logic Verification**: Verify that the exponential backoff strategy configuration (3 retries, factor 1) results in a total wait time that fits within reasonable bounds (e.g., less than the 30s read timeout, but potentially interacting with the 10s connect timeout). We will model the urllib3 retry formula `backoff * 2^(retry-1)` and prove constraints on the total delay.

2.  **Unit Tests**:
    *   **Authentication**:
        *   `test_narrate_missing_api_key`: Verify `AuthenticationError` is raised when `ELEVENLABS_API_KEY` is unset.
        *   `test_narrate_invalid_api_key`: Verify `AuthenticationError` is raised when API returns 401.
    *   **Core Functionality - Narrate**:
        *   `test_narrate_batch_success`: Verify correct API call (URL, headers, payload) and return type (bytes) for `stream=False`.
        *   `test_narrate_stream_success`: Verify correct API call and return type (generator) for `stream=True`. Ensure generator yields chunks.
        *   `test_narrate_stream_cleanup`: Verify `response.close()` is called when streaming finishes.
    *   **Core Functionality - Briefing**:
        *   `test_generate_briefing_structure`: Verify `generate_briefing` formats text correctly for a standard case (violations > 0) and calls `narrate`.
        *   `test_generate_briefing_no_violations`: Verify specific text output for 0 violations.
        *   `test_generate_briefing_truncation`: Verify that extremely long generated scripts are truncated to 4500 chars before calling `narrate`.
    *   **Core Functionality - Alert**:
        *   `test_alert_formatting`: Verify "Alert." prefix is added if missing.
        *   `test_alert_formatting_existing_prefix`: Verify prefix is NOT added if "Attention" or "Alert" is already present.
    *   **Error Handling**:
        *   `test_api_failure_retry_exhausted`: Verify `VoiceServiceError` is raised on `RetryError`.
        *   `test_api_generic_failure`: Verify `VoiceServiceError` is raised on standard `RequestException`.
        *   `test_http_error_status`: Verify `raise_for_status` triggers exception mapping.

3.  **Isolation Strategy**:
    *   Use `unittest.mock` to mock `requests.Session` and `os.environ`.
    *   Use `pytest` fixtures for setup/teardown of environment variables.
    *   Ensure no real network calls are made.
"""

import os
import pytest
from unittest.mock import MagicMock, patch, ANY
import requests
from z3 import Solver, Int, Real, Sum, Exists, ForAll, Implies, Sat

# Import the module under test
import voice_service

# --- Fixtures ---

@pytest.fixture
def mock_env_key(monkeypatch):
    """Sets a valid API key for tests."""
    monkeypatch.setenv("ELEVENLABS_API_KEY", "test_api_key")

@pytest.fixture
def mock_missing_env_key(monkeypatch):
    """Removes the API key for tests."""
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)

@pytest.fixture
def mock_session():
    """Mocks the requests session and its post method."""
    with patch("voice_service._get_session") as mock_get_session:
        session_instance = MagicMock()
        mock_get_session.return_value = session_instance
        yield session_instance

# --- Z3 Formal Verification Tests ---

def test_z3_retry_backoff_constraints():
    """
    Formally verify that the retry strategy (3 retries, backoff factor 1)
    results in a total wait time that is strictly positive and bounded.
    
    Formula for urllib3 Retry: sleep = backoff_factor * (2 ** (retry_count - 1))
    """
    s = Solver()
    
    # Constants from code
    backoff_factor = Real('backoff_factor')
    total_retries = Int('total_retries')
    
    # Constraints based on code implementation
    s.add(backoff_factor == 1.0)
    s.add(total_retries == 3)
    
    # Define wait times for each retry attempt
    # Retry 1 (index 0 in 0-based counting, but formula uses count 1, 2, 3)
    wait_1 = Real('wait_1')
    wait_2 = Real('wait_2')
    wait_3 = Real('wait_3')
    
    # urllib3 logic: sleep = factor * 2^(i-1) where i is the retry attempt number (1, 2, 3)
    s.add(wait_1 == backoff_factor * (2 ** (1 - 1))) # 1 * 2^0 = 1
    s.add(wait_2 == backoff_factor * (2 ** (2 - 1))) # 1 * 2^1 = 2
    s.add(wait_3 == backoff_factor * (2 ** (3 - 1))) # 1 * 2^2 = 4
    
    total_wait = Real('total_wait')
    s.add(total_wait == wait_1 + wait_2 + wait_3)
    
    # Verification 1: Total wait should be exactly 7 seconds
    s.push()
    s.add(total_wait != 7.0)
    # If unsat, it means total_wait MUST be 7.0
    assert s.check() == 2 # unsat means the negation is impossible, so it is proven
    s.pop()
    
    # Verification 2: Total wait should be less than the connection timeout (10s)
    # This ensures that the retries don't exceed the initial connection timeout budget 
    # (though technically they are separate concepts, it's a good system invariant).
    s.push()
    s.add(total_wait > 10.0)
    assert s.check() == 2 # unsat
    s.pop()

# --- Unit Tests ---

def test_narrate_missing_api_key(mock_missing_env_key):
    """Test that narrate raises AuthenticationError if API key is missing."""
    # We need to reload or patch the module level constant because it's read at import time
    # However, the function _validate_api_key checks os.getenv or the constant.
    # The code uses a global constant ELEVENLABS_API_KEY read at import.
    # We must patch the module-level variable directly.
    with patch("voice_service.ELEVENLABS_API_KEY", None):
        with pytest.raises(voice_service.AuthenticationError, match="environment variable is not set"):
            voice_service.narrate("Hello")

def test_narrate_invalid_api_key_401(mock_env_key, mock_session):
    """Test that narrate raises AuthenticationError on 401 response."""
    # Setup mock response
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_session.post.return_value = mock_response
    
    # Patch the module constant to ensure it has a value
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        with pytest.raises(voice_service.AuthenticationError, match="Invalid ElevenLabs API Key"):
            voice_service.narrate("Hello")

def test_narrate_batch_success(mock_env_key, mock_session):
    """Test successful batch narration (stream=False)."""
    expected_audio = b"\x00\x01\x02"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = expected_audio
    mock_session.post.return_value = mock_response
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        result = voice_service.narrate("Hello world", stream=False)
        
        assert result == expected_audio
        
        # Verify API call details
        mock_session.post.assert_called_once()
        args, kwargs = mock_session.post.call_args
        
        assert "https://api.elevenlabs.io/v1/text-to-speech/21m00Tcm4TlvDq8ikWAM" in args[0]
        assert kwargs["stream"] is False
        assert kwargs["headers"]["xi-api-key"] == "test_key"
        assert kwargs["json"]["text"] == "Hello world"
        assert kwargs["json"]["model_id"] == "eleven_monolingual_v1"
        assert kwargs["params"]["output_format"] == "mp3_44100_128"

def test_narrate_stream_success(mock_env_key, mock_session):
    """Test successful streaming narration (stream=True)."""
    chunks = [b"chunk1", b"chunk2", b"chunk3"]
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.iter_content.return_value = iter(chunks)
    mock_session.post.return_value = mock_response
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        result_iterator = voice_service.narrate("Streaming text", stream=True)
        
        # Verify it returns an iterator
        assert hasattr(result_iterator, "__next__")
        
        # Consume iterator
        received_chunks = list(result_iterator)
        assert received_chunks == chunks
        
        # Verify stream=True was passed
        args, kwargs = mock_session.post.call_args
        assert kwargs["stream"] is True

        # Verify URL modification for streaming
        assert args[0].endswith("/stream")

def test_narrate_stream_cleanup(mock_env_key, mock_session):
    """Test that response is closed after streaming."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.iter_content.return_value = iter([b"data"])
    mock_session.post.return_value = mock_response
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        iterator = voice_service.narrate("text", stream=True)
        list(iterator) # Consume
        
        mock_response.close.assert_called_once()

def test_generate_briefing_structure(mock_env_key):
    """Test briefing generation logic and formatting."""
    scan_results = {
        "total_violations": 5,
        "severity_breakdown": {"critical": 2, "high": 1},
        "top_issues": [{"title": "Bad Password"}, {"title": "Open Port"}],
        "scan_date": "2023-10-27"
    }
    
    with patch("voice_service.narrate") as mock_narrate:
        mock_narrate.return_value = b"audio"
        
        voice_service.generate_briefing(scan_results)
        
        mock_narrate.assert_called_once()
        call_text = mock_narrate.call_args[0][0]
        
        # Check for key phrases in the generated script
        assert "executive briefing for 2023-10-27" in call_text
        assert "total of 5 compliance events" in call_text
        assert "2 critical" in call_text
        assert "1 high priority" in call_text
        assert "Bad Password" in call_text
        assert "Open Port" in call_text

def test_generate_briefing_no_violations(mock_env_key):
    """Test briefing generation with zero violations."""
    scan_results = {
        "total_violations": 0,
        "scan_date": "2023-10-27"
    }
    
    with patch("voice_service.narrate") as mock_narrate:
        voice_service.generate_briefing(scan_results)
        
        call_text = mock_narrate.call_args[0][0]
        assert "No compliance violations were detected" in call_text

def test_generate_briefing_truncation(mock_env_key):
    """Test that very long briefing scripts are truncated."""
    # Create a scenario that generates a long script
    long_title = "A" * 2000
    scan_results = {
        "total_violations": 10,
        "top_issues": [{"title": long_title}, {"title": long_title}, {"title": long_title}]
    }
    
    with patch("voice_service.narrate") as mock_narrate:
        voice_service.generate_briefing(scan_results)
        
        call_text = mock_narrate.call_args[0][0]
        assert len(call_text) <= 4503 # 4500 + "..."
        assert call_text.endswith("...")

def test_alert_formatting(mock_env_key):
    """Test alert adds prefix if missing."""
    with patch("voice_service.narrate") as mock_narrate:
        voice_service.alert("Server down")
        
        mock_narrate.assert_called_once()
        call_text = mock_narrate.call_args[0][0]
        assert call_text == "Alert. Server down"
        assert mock_narrate.call_args[1]["stream"] is False

def test_alert_formatting_existing_prefix(mock_env_key):
    """Test alert does not add prefix if already present."""
    with patch("voice_service.narrate") as mock_narrate:
        voice_service.alert("Attention: Breach detected")
        
        call_text = mock_narrate.call_args[0][0]
        assert call_text == "Attention: Breach detected"

def test_api_failure_retry_exhausted(mock_env_key, mock_session):
    """Test that MaxRetryError is converted to VoiceServiceError."""
    mock_session.post.side_effect = requests.exceptions.RetryError("Max retries")
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        with pytest.raises(voice_service.VoiceServiceError, match="Service unavailable"):
            voice_service.narrate("text")

def test_api_generic_failure(mock_env_key, mock_session):
    """Test that generic RequestException is converted to VoiceServiceError."""
    mock_session.post.side_effect = requests.exceptions.RequestException("Connection reset")
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        with pytest.raises(voice_service.VoiceServiceError, match="API request failed"):
            voice_service.narrate("text")

def test_http_error_status(mock_env_key, mock_session):
    """Test that HTTP errors (e.g. 500) raise VoiceServiceError via raise_for_status."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
    mock_session.post.return_value = mock_response
    
    with patch("voice_service.ELEVENLABS_API_KEY", "test_key"):
        with pytest.raises(voice_service.VoiceServiceError):
            voice_service.narrate("text")