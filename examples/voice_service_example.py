import os
import sys
import time

# Ensure the src directory is in the python path so we can import the module
# This assumes the example script is run from the project root or a sibling directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

try:
    import voice_service
except ImportError:
    print("Error: Could not import 'voice_service'. Make sure 'src/voice_service.py' exists.")
    sys.exit(1)

def save_audio_file(audio_data: bytes, filename: str):
    """Helper to save audio bytes to a file."""
    with open(filename, "wb") as f:
        f.write(audio_data)
    print(f"Saved audio to: {filename} ({len(audio_data)} bytes)")

def run_example():
    # 1. Check for API Key
    if not os.getenv("ELEVENLABS_API_KEY"):
        print("Error: ELEVENLABS_API_KEY environment variable is not set.")
        print("Please set it to run this example.")
        return

    print("--- RegWatch Voice Service Example ---\n")

    # ---------------------------------------------------------
    # Example 1: Generate an Urgent Alert (Batch Mode)
    # ---------------------------------------------------------
    print("1. Generating Urgent Alert...")
    alert_msg = "Unauthorized access detected in sector 7G. Immediate containment required."
    
    try:
        # The alert function adds tone markers and returns complete bytes
        alert_audio = voice_service.alert(alert_msg)
        save_audio_file(alert_audio, "alert_output.mp3")
    except Exception as e:
        print(f"Failed to generate alert: {e}")

    print("\n" + "-"*40 + "\n")

    # ---------------------------------------------------------
    # Example 2: Generate an Executive Briefing (Batch Mode)
    # ---------------------------------------------------------
    print("2. Generating Executive Briefing...")
    
    # Mock data representing a compliance scan result
    scan_data = {
        "compliance_score": "85/100",
        "total_violations": 12,
        "severity_breakdown": {
            "critical": 2,
            "high": 4,
            "medium": 5,
            "low": 1
        },
        "top_issues": [
            {"description": "Unencrypted S3 bucket detected"},
            {"description": "Root account usage without MFA"},
            {"description": "Outdated SSL certificate on load balancer"}
        ]
    }

    try:
        # This function formats the dict into a script and generates audio
        briefing_audio = voice_service.generate_briefing(scan_data)
        save_audio_file(briefing_audio, "briefing_output.mp3")
    except Exception as e:
        print(f"Failed to generate briefing: {e}")

    print("\n" + "-"*40 + "\n")

    # ---------------------------------------------------------
    # Example 3: Real-time Streaming Narration
    # ---------------------------------------------------------
    print("3. Streaming Narration (Simulated Playback)...")
    
    long_text = (
        "Initiating deep scan of cloud infrastructure. "
        "Analyzing security groups for open ports. "
        "Checking IAM policies for permissive roles. "
        "Scan complete. No critical vulnerabilities found in this segment."
    )

    try:
        # stream=True returns a generator instead of bytes
        audio_stream = voice_service.narrate(long_text, stream=True)
        
        print("Stream started. Receiving chunks:")
        total_bytes = 0
        chunk_count = 0
        
        # In a real app, you would pipe these chunks to an audio player (e.g., PyAudio or ffplay)
        with open("stream_output.mp3", "wb") as f:
            for chunk in audio_stream:
                f.write(chunk)
                total_bytes += len(chunk)
                chunk_count += 1
                # Print a dot for every chunk received to visualize streaming
                print(".", end="", flush=True)
        
        print(f"\nStream finished. Received {chunk_count} chunks, totaling {total_bytes} bytes.")
        print("Saved stream output to: stream_output.mp3")

    except Exception as e:
        print(f"\nStreaming failed: {e}")

if __name__ == "__main__":
    run_example()