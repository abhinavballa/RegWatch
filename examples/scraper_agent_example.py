import os
import sys
import json
import logging

# Ensure the module can be imported by adding the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.agents import scraper_agent
except ImportError:
    print("Error: 'scraper_agent.py' not found. Please ensure the module file exists.")
    sys.exit(1)

# Configure logging to see the agent's activity
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RegWatchExample")

def main():
    """
    Demonstrates the usage of the RegWatch Scraper Agent.
    """
    
    # 1. Setup Environment
    # The module requires the TOOLHOUSE_API_KEY to function.
    if not os.getenv("TOOLHOUSE_API_KEY"):
        logger.warning("TOOLHOUSE_API_KEY not set. Setting a dummy key for demonstration.")
        os.environ["TOOLHOUSE_API_KEY"] = "dummy_key_for_demo"

    print("\n--- 1. Monitoring Regulations ---")
    print("Scanning default sources (HHS, FDA, Federal Register) for new HIPAA updates...")
    
    # The monitor_regulations function is the main entry point.
    # It handles searching, deduplication against the change_tracker, and extraction.
    try:
        new_regulations = scraper_agent.monitor_regulations()
        
        if new_regulations:
            print(f"\nFound {len(new_regulations)} new regulations:")
            for reg in new_regulations:
                print(f" - [{reg['regulation_id']}] {reg['title']} ({reg['publication_date']})")
        else:
            print("\nNo new regulations found (or mock search returned empty).")
            
    except Exception as e:
        logger.error(f"Monitoring failed: {e}")

    print("\n--- 2. Extracting Specific Regulation ---")
    # If you have a specific URL you want to process directly (bypassing monitoring/search):
    target_url = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"
    print(f"Extracting details from specific URL: {target_url}")

    try:
        # extract_regulation pulls metadata and full text from a single URL.
        # It includes rate limiting and retry logic automatically.
        reg_details = scraper_agent.extract_regulation(target_url)
        
        print("\nExtraction Result:")
        print(json.dumps(reg_details, indent=2))
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")

if __name__ == "__main__":
    main()