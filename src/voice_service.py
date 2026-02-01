"""
RegWatch Voice Service Module
=============================

This module provides text-to-speech (TTS) capabilities for the RegWatch compliance 
monitoring system using the ElevenLabs API. It supports real-time streaming for 
scan narration and batch processing for executive briefings and alerts.

Key Features:
- Integration with ElevenLabs Text-to-Speech API
- "Rachel" voice profile (ID: 21m00Tcm4TlvDq8ikWAM) with professional tone
- Streaming support for low-latency audio playback
- Automatic retry logic with exponential backoff for network resilience
- Structured briefing generation from raw scan data

Configuration:
- Requires ELEVENLABS_API_KEY environment variable
- Outputs MP3 audio at 44.1kHz
"""

import os
import json
import time
import logging
from typing import Union, Iterator, Dict, Optional, Any

import requests
from requests.exceptions import RequestException, HTTPError

# Configure logging
logger = logging.getLogger(__name__)

# Constants
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
BASE_URL = "https://api.elevenlabs.io/v1/text-to-speech"
VOICE_ID_RACHEL = "21m00Tcm4TlvDq8ikWAM"

# Audio Settings
MODEL_ID = "eleven_monolingual_v1"
OUTPUT_FORMAT = "mp3_44100_128"

# Voice Settings (Professional Tone)
VOICE_SETTINGS = {
    "stability": 0.5,       # Balanced stability
    "similarity_boost": 0.75, # Higher clarity/professionalism
    "style": 0.0,
    "use_speaker_boost": True
}

class VoiceServiceError(Exception):
    """Base exception for voice service failures."""
    pass

class AuthenticationError(VoiceServiceError):
    """Raised when API key is invalid or missing."""
    pass

class RateLimitError(VoiceServiceError):
    """Raised when API rate limits are exceeded."""
    pass

def _get_headers(stream: bool = False) -> Dict[str, str]:
    """
    Constructs headers for ElevenLabs API requests.
    
    Args:
        stream: Whether the request is for streaming audio.
    
    Returns:
        Dictionary of HTTP headers.
        
    Raises:
        AuthenticationError: If ELEVENLABS_API_KEY is not set.
    """
    if not ELEVENLABS_API_KEY:
        raise AuthenticationError("ELEVENLABS_API_KEY environment variable is not set.")
    
    headers = {
        "xi-api-key": ELEVENLABS_API_KEY,
        "Content-Type": "application/json"
    }
    
    # Optimization for streaming latency
    if stream:
        headers["Accept"] = "audio/mpeg"
        
    return headers

def _make_request_with_retry(
    url: str, 
    payload: Dict[str, Any], 
    stream: bool = False, 
    max_retries: int = 3
) -> requests.Response:
    """
    Executes HTTP POST request with exponential backoff retry logic.
    
    Args:
        url: The API endpoint URL.
        payload: The JSON payload.
        stream: Whether to stream the response.
        max_retries: Number of retry attempts.
        
    Returns:
        The requests.Response object.
        
    Raises:
        VoiceServiceError: On persistent failure after retries.
    """
    attempt = 0
    last_error = None

    while attempt <= max_retries:
        try:
            headers = _get_headers(stream=stream)
            
            # Set timeout: shorter for streaming connection, longer for batch generation
            timeout = (5, 30) if stream else 30
            
            response = requests.post(
                url, 
                json=payload, 
                headers=headers, 
                stream=stream,
                timeout=timeout
            )
            
            # Handle specific HTTP errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid ElevenLabs API Key.")
            elif response.status_code == 429:
                raise RateLimitError("ElevenLabs API rate limit exceeded.")
            
            response.raise_for_status()
            return response

        except (RequestException, HTTPError) as e:
            last_error = e
            # Don't retry on Auth errors
            if isinstance(e, AuthenticationError):
                raise e
                
            attempt += 1
            if attempt <= max_retries:
                sleep_time = 2 ** (attempt - 1) # 1s, 2s, 4s
                logger.warning(f"API request failed. Retrying in {sleep_time}s... (Attempt {attempt}/{max_retries})")
                time.sleep(sleep_time)
            else:
                logger.error(f"API request failed after {max_retries} retries: {str(e)}")

    raise VoiceServiceError(f"Failed to generate audio after retries: {str(last_error)}")

def narrate(text: str, stream: bool = False) -> Union[bytes, Iterator[bytes]]:
    """
    Converts text to speech using the Rachel voice profile.
    
    Args:
        text: The text content to narrate.
        stream: If True, returns a generator yielding audio chunks. 
                If False, returns the complete audio bytes.
    
    Returns:
        Audio data as bytes (MP3) or an iterator of bytes.
    """
    if not text or not text.strip():
        logger.warning("Empty text provided to narrate function.")
        return b"" if not stream else iter([])

    url = f"{BASE_URL}/{VOICE_ID_RACHEL}"
    if stream:
        url += "/stream"
    
    # Add query param for optimization
    url += f"?optimize_streaming_latency={3 if stream else 0}&output_format={OUTPUT_FORMAT}"

    payload = {
        "text": text,
        "model_id": MODEL_ID,
        "voice_settings": VOICE_SETTINGS
    }

    try:
        response = _make_request_with_retry(url, payload, stream=stream)

        if stream:
            def audio_generator():
                try:
                    # Chunk size of 1024 bytes is standard for audio streaming
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            yield chunk
                finally:
                    response.close()
            return audio_generator()
        else:
            return response.content

    except VoiceServiceError as e:
        logger.error(f"Narration failed: {e}")
        raise

def _format_briefing_text(scan_results: Dict[str, Any]) -> str:
    """
    Converts structured scan results into a natural language script for narration.
    
    Args:
        scan_results: Dictionary containing scan metrics and violations.
        
    Returns:
        Formatted string script.
    """
    total_violations = scan_results.get("total_violations", 0)
    severity_counts = scan_results.get("severity_breakdown", {"critical": 0, "high": 0, "medium": 0, "low": 0})
    top_issues = scan_results.get("top_issues", [])
    compliance_score = scan_results.get("compliance_score", "unknown")

    # Intro
    script = (
        f"Here is your RegWatch executive briefing. The latest compliance scan resulted in a score of {compliance_score}. "
        f"We detected a total of {total_violations} violations across the monitored infrastructure. "
    )

    # Severity Breakdown
    if total_violations > 0:
        script += "Breaking this down by severity: "
        parts = []
        if severity_counts.get("critical", 0) > 0:
            parts.append(f"{severity_counts['critical']} critical issues")
        if severity_counts.get("high", 0) > 0:
            parts.append(f"{severity_counts['high']} high priority issues")
        
        if parts:
            script += ", and ".join(parts) + ". "
        else:
            script += "mostly medium to low priority findings. "

    # Top Issues
    if top_issues:
        script += "The most pressing issues requiring immediate attention are: "
        for i, issue in enumerate(top_issues[:3], 1):
            script += f"Number {i}: {issue.get('description', 'Unknown issue')}. "

    # Outro
    script += "Please review the full report in the dashboard for remediation steps."
    
    return script

def generate_briefing(scan_results: Dict[str, Any]) -> bytes:
    """
    Generates a 2-3 minute executive summary audio from scan results.
    
    Args:
        scan_results: Dictionary containing scan data (violations, severity, etc).
        
    Returns:
        Complete MP3 audio bytes.
    """
    logger.info("Generating executive briefing audio.")
    script = _format_briefing_text(scan_results)
    
    # Ensure script fits within API limits (approx 5000 chars)
    if len(script) > 4500:
        logger.warning("Briefing script too long, truncating.")
        script = script[:4500] + "... See full report for details."

    # Briefings are batch processed, not streamed
    return narrate(script, stream=False)

def alert(message: str) -> bytes:
    """
    Generates a short, urgent audio alert (10-15 seconds).
    
    Args:
        message: The alert message text.
        
    Returns:
        Complete MP3 audio bytes.
    """
    logger.info(f"Generating alert audio for: {message[:50]}...")
    
    # Prepend attention marker for TTS tone
    urgent_message = f"Attention. RegWatch Alert. {message}"
    
    # Alerts are short and should be returned as a complete file
    return narrate(urgent_message, stream=False)"
}```