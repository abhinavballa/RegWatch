"""
RegWatch Voice Service Module

This module provides text-to-speech capabilities for the RegWatch compliance monitoring system
using the ElevenLabs API. It supports real-time streaming for scan narration and batch
processing for executive briefings and alerts.

Key Features:
- Integration with ElevenLabs Text-to-Speech API
- Streaming support for low-latency audio playback
- Automatic retry logic with exponential backoff for network resilience
- Specialized formatting for compliance scan summaries
- Consistent "Rachel" voice profile with professional tone settings

Configuration:
- Requires ELEVENLABS_API_KEY environment variable
- Defaults to MP3 44.1kHz output format
"""

import os
import json
import time
import logging
from typing import Union, Iterator, Dict, Optional, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)

# Constants
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
VOICE_ID_RACHEL = "21m00Tcm4TlvDq8ikWAM"
BASE_URL = "https://api.elevenlabs.io/v1/text-to-speech"
MODEL_ID = "eleven_monolingual_v1"  # Reliable model for English narration

# Audio Settings
OUTPUT_FORMAT = "mp3_44100_128"  # High quality MP3
VOICE_SETTINGS = {
    "stability": 0.5,       # Balanced for natural but consistent speech
    "similarity_boost": 0.75, # Higher boost for professional clarity
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

def _get_session() -> requests.Session:
    """
    Creates a requests session with retry logic for resilience.
    
    Returns:
        requests.Session: Configured session object
    """
    session = requests.Session()
    
    # Retry strategy: 3 retries, exponential backoff (1s, 2s, 4s)
    # Status codes: 429 (Rate Limit), 500/502/503/504 (Server Errors)
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    return session

def _validate_api_key():
    """Validates that the API key is present in environment variables."""
    if not ELEVENLABS_API_KEY:
        raise AuthenticationError("ELEVENLABS_API_KEY environment variable is not set.")

def _format_briefing_text(scan_results: Dict[str, Any]) -> str:
    """
    Converts structured scan results into a natural language script for narration.
    
    Args:
        scan_results: Dictionary containing scan metrics (total_violations, severity breakdown, etc.)
        
    Returns:
        str: Formatted text script suitable for TTS.
    """
    total_violations = scan_results.get("total_violations", 0)
    severity = scan_results.get("severity_breakdown", {"critical": 0, "high": 0, "medium": 0, "low": 0})
    top_issues = scan_results.get("top_issues", [])
    scan_date = scan_results.get("scan_date", "today")

    # Intro
    script = [f"Here is your RegWatch executive briefing for {scan_date}."]
    
    # Summary
    if total_violations == 0:
        script.append("Great news. No compliance violations were detected in the latest scan.")
        return " ".join(script)
    
    script.append(f"The system detected a total of {total_violations} compliance events requiring attention.")
    
    # Severity Breakdown
    breakdown_text = []
    if severity.get("critical", 0) > 0:
        breakdown_text.append(f"{severity['critical']} critical")
    if severity.get("high", 0) > 0:
        breakdown_text.append(f"{severity['high']} high priority")
        
    if breakdown_text:
        script.append(f"Most urgently, we found {', and '.join(breakdown_text)} issues.")
    
    # Top Issues
    if top_issues:
        script.append("The top issues include:")
        for i, issue in enumerate(top_issues[:3], 1):
            script.append(f"Number {i}: {issue.get('title', 'Unknown issue')}.")
            
    script.append("Please review the full report in the dashboard for remediation steps.")
    
    return " ".join(script)

def narrate(text: str, stream: bool = False) -> Union[bytes, Iterator[bytes]]:
    """
    Converts text to speech using the ElevenLabs API.
    
    Args:
        text: The text content to convert to audio.
        stream: If True, returns a generator yielding audio chunks. 
                If False, returns the complete audio bytes.
                
    Returns:
        Union[bytes, Iterator[bytes]]: Audio data in MP3 format.
        
    Raises:
        VoiceServiceError: On API failures after retries.
    """
    _validate_api_key()
    
    url = f"{BASE_URL}/{VOICE_ID_RACHEL}"
    if stream:
        url += "/stream"
        
    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY
    }
    
    payload = {
        "text": text,
        "model_id": MODEL_ID,
        "voice_settings": VOICE_SETTINGS
    }
    
    # Add output format param to URL query
    params = {"output_format": OUTPUT_FORMAT}
    
    session = _get_session()
    
    try:
        # Set timeout: 10s connect, 30s read (longer for batch generation)
        timeout = (10, 30) 
        
        response = session.post(
            url, 
            json=payload, 
            headers=headers, 
            params=params, 
            stream=stream,
            timeout=timeout
        )
        
        if response.status_code == 401:
            raise AuthenticationError("Invalid ElevenLabs API Key.")
        
        response.raise_for_status()
        
        if stream:
            # Return an iterator that yields chunks and handles cleanup
            def audio_generator():
                try:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            yield chunk
                except Exception as e:
                    logger.error(f"Error during audio streaming: {e}")
                    raise VoiceServiceError(f"Streaming interrupted: {e}")
                finally:
                    response.close()
            return audio_generator()
        else:
            # Return full bytes
            return response.content
            
    except requests.exceptions.RetryError:
        logger.error("Max retries exceeded for ElevenLabs API")
        raise VoiceServiceError("Service unavailable after multiple attempts.")
    except requests.exceptions.RequestException as e:
        logger.error(f"ElevenLabs API request failed: {e}")
        raise VoiceServiceError(f"API request failed: {str(e)}")

def generate_briefing(scan_results: Dict[str, Any]) -> bytes:
    """
    Generates a 2-3 minute executive summary audio from scan results.
    
    Args:
        scan_results: Dictionary containing scan metrics and issues.
        
    Returns:
        bytes: Complete MP3 audio file content.
    """
    logger.info("Generating executive briefing audio...")
    
    script = _format_briefing_text(scan_results)
    
    # Ensure script isn't too long for a single request (approx limit check)
    if len(script) > 4500:
        logger.warning("Briefing script too long, truncating to 4500 chars.")
        script = script[:4500] + "..."
        
    # Briefings are always batch mode (stream=False)
    return narrate(script, stream=False)

def alert(message: str) -> bytes:
    """
    Generates a short, urgent audio alert (10-15 seconds).
    
    Args:
        message: Concise alert message text.
        
    Returns:
        bytes: Complete MP3 audio file content.
    """
    logger.info(f"Generating alert audio for: {message[:50]}...")
    
    # Prepend an attention marker text if not present to ensure tone
    if not message.lower().startswith("attention") and not message.lower().startswith("alert"):
        formatted_message = f"Alert. {message}"
    else:
        formatted_message = message
        
    # Alerts are batch mode, usually short
    return narrate(formatted_message, stream=False)"}