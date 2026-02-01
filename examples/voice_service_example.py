import os
import sys
import time

# Ensure the module can be imported from the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the module functions
# Note: Replace 'voice_service' with the actual filename if different
import voice_service

def main():
    """
    Demonstrates the usage of the RegWatch Voice Service for generating alerts,
    streaming narration, and creating executive briefings.
    """
    # 1. Setup: Ensure API Key is present
    if not os.getenv("ELEVENLABS_API_KEY"):
        print("Error: ELEVENLABS_API_KEY environment variable is required.")
        return

    print("--- RegWatch Voice Service Demo ---\n")

    # ---------------------------------------------------------
    # Example 1: Generating a High-Priority Alert (Batch Mode)
    # ---------------------------------------------------------
    print("1. Generating Security Alert...")
    try:
        alert_msg = "Critical vulnerability detected in payment gateway subnet."
        audio_data = voice_service.alert(alert_msg)
        
        # Save the binary audio data to a file
        filename = "alert.mp3"
        with open(filename, "wb") as f:
            f.write(audio_data)
        print(f"   Success: Alert saved to {filename} ({len(audio_data)} bytes)")

    except voice_service.VoiceServiceError as e:
        print(f"   Error generating alert: {e}")

    # ---------------------------------------------------------
    # Example 2: Streaming Narration (Real-time)
    # ---------------------------------------------------------
    print("\n2. Streaming Live Narration...")
    try:
        text_to_stream = (
            "Initiating deep scan of sector 7. "
            "Analyzing firewall rules against updated compliance framework. "
            "No anomalies detected so far."
        )
        
        # narrate(stream=True) returns a generator
        audio_stream = voice_service.narrate(text_to_stream, stream=True)
        
        # In a real app, you would pipe these chunks to an audio player (e.g., PyAudio or ffplay)
        # Here we simulate receiving chunks
        chunk_count = 0
        total_bytes = 0
        
        print("   Receiving audio stream...", end="", flush=True)
        for chunk in audio_stream:
            chunk_count += 1
            total_bytes += len(chunk)
            # Simulate playback buffering
            if chunk_count % 5 == 0:
                print(".", end="", flush=True)
        
        print(f"\n   Stream complete: Received {chunk_count} chunks ({total_bytes} bytes)")

    except voice_service.VoiceServiceError as e:
        print(f"\n   Streaming error: {e}")

    # ---------------------------------------------------------
    # Example 3: Generating an Executive Briefing
    # ---------------------------------------------------------
    print("\n3. Generating Executive Briefing...")
    
    # Mock data representing a compliance scan result
    scan_data = {
        "compliance_score": "85/100",
        "total_violations": 12,
        "severity_breakdown": {
            "critical": 2,
            "high": 4,
            "medium": 6,
            "low": 0
        },
        "top_issues": [
            {"description": "Unencrypted S3 bucket detected"},
            {"description": "Root account usage without MFA"},
            {"description": "Outdated SSL certificate on load balancer"}
        ]
    }

    try:
        # This function handles the text formatting internally
        briefing_audio = voice_service.generate_briefing(scan_data)
        
        filename = "briefing.mp3"
        with open(filename, "wb") as f:
            f.write(briefing_audio)
        print(f"   Success: Executive briefing saved to {filename}")

    except voice_service.VoiceServiceError as e:
        print(f"   Error generating briefing: {e}")

if __name__ == "__main__":
    main()