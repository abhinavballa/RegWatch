import os
import sys
import time

# Ensure the module can be imported (assuming it's in the same directory)
sys.path.append(os.path.dirname(__file__))

# Import the module (assuming the file is named voice_service.py)
import voice_service

def main():
    # 1. Setup: Ensure API Key is present
    if not os.getenv("ELEVENLABS_API_KEY"):
        print("Error: ELEVENLABS_API_KEY environment variable must be set.")
        return

    print("--- RegWatch Voice Service Demo ---\n")

    # ---------------------------------------------------------
    # Example 1: Generating a Short Alert (Batch Mode)
    # ---------------------------------------------------------
    print("1. Generating urgent alert audio...")
    try:
        alert_msg = "Critical violation detected in Payment Gateway module. Immediate action required."
        audio_data = voice_service.alert(alert_msg)
        
        # Save to file to verify output
        filename = "alert_output.mp3"
        with open(filename, "wb") as f:
            f.write(audio_data)
        print(f"   Success! Alert saved to {filename} ({len(audio_data)} bytes)")
        
    except voice_service.VoiceServiceError as e:
        print(f"   Failed to generate alert: {e}")

    # ---------------------------------------------------------
    # Example 2: Generating an Executive Briefing (Batch Mode)
    # ---------------------------------------------------------
    print("\n2. Generating executive briefing from scan results...")
    
    # Mock data representing a compliance scan
    scan_data = {
        "scan_date": "October 27, 2023",
        "total_violations": 5,
        "severity_breakdown": {
            "critical": 1,
            "high": 2,
            "medium": 2,
            "low": 0
        },
        "top_issues": [
            {"title": "Unencrypted PII in logs"},
            {"title": "Missing MFA on admin portal"},
            {"title": "Outdated SSL certificate"}
        ]
    }

    try:
        # This function handles the text formatting internally
        briefing_audio = voice_service.generate_briefing(scan_data)
        
        filename = "briefing_output.mp3"
        with open(filename, "wb") as f:
            f.write(briefing_audio)
        print(f"   Success! Briefing saved to {filename} ({len(briefing_audio)} bytes)")

    except voice_service.VoiceServiceError as e:
        print(f"   Failed to generate briefing: {e}")

    # ---------------------------------------------------------
    # Example 3: Streaming Narration (Real-time Mode)
    # ---------------------------------------------------------
    print("\n3. Streaming live narration...")
    
    long_text = (
        "Initiating deep scan of the user database. "
        "Checking for encryption standards compliance. "
        "Analyzing access logs for anomalies. "
        "Scan complete. No irregularities found."
    )

    try:
        # stream=True returns a generator
        audio_stream = voice_service.narrate(long_text, stream=True)
        
        filename = "stream_output.mp3"
        with open(filename, "wb") as f:
            chunk_count = 0
            total_bytes = 0
            
            print("   Receiving chunks", end="", flush=True)
            for chunk in audio_stream:
                f.write(chunk)
                chunk_count += 1
                total_bytes += len(chunk)
                if chunk_count % 5 == 0:
                    print(".", end="", flush=True)
            
        print(f"\n   Success! Streamed {total_bytes} bytes to {filename}")

    except voice_service.VoiceServiceError as e:
        print(f"\n   Streaming failed: {e}")

if __name__ == "__main__":
    main()