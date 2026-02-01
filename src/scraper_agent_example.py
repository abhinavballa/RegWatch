import os
import sys
import logging
from typing import List, Dict, Any

# Ensure the src directory is in the python path so we can import the agent
# Adjust this path based on where this script is located relative to src/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

try:
    from src.agents import scraper_agent
except ImportError:
    # Fallback if running directly next to the file for testing
    import scraper_agent

# Configure logging to see the agent's activity
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RegWatch-Example")

def run_monitoring_cycle():
    """
    Demonstrates the primary use case: Monitoring default sources for new regulations.
    """
    logger.info("--- Starting Monitoring Cycle ---")
    
    # Ensure API key is set (Toolhouse SDK requirement)
    if not os.getenv("TOOLHOUSE_API_KEY"):
        logger.warning("TOOLHOUSE_API_KEY not set. The agent may use mock data or fail.")
        # For demonstration purposes, we might set a dummy key if the module mocks it
        os.environ["TOOLHOUSE_API_KEY"] = "dummy-key-for-demo"

    # 1. Monitor default sources (HHS, FDA, Federal Register)
    # This function handles:
    # - Searching via Toolhouse
    # - Deduplicating against the change_tracker
    # - Rate limiting
    new_regulations = scraper_agent.monitor_regulations()

    if not new_regulations:
        logger.info("No new regulations found in this cycle.")
    else:
        logger.info(f"Found {len(new_regulations)} new regulations:")
        for reg in new_regulations:
            print_regulation_summary(reg)

def extract_specific_regulation():
    """
    Demonstrates the secondary use case: Extracting a specific known URL.
    Useful for manual triggers or re-processing.
    """
    logger.info("\n--- Extracting Specific Regulation ---")
    
    target_url = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"
    
    # 2. Extract data from a specific URL
    # This performs the fetch, cleans HTML, and parses metadata
    reg_data = scraper_agent.extract_regulation(target_url)

    if reg_data:
        logger.info("Successfully extracted regulation.")
        print_regulation_summary(reg_data)
    else:
        logger.error(f"Failed to extract data from {target_url}")

def print_regulation_summary(reg: Dict[str, Any]):
    """Helper to pretty-print regulation data."""
    print(f"\n[ID]: {reg.get('regulation_id')}")
    print(f"[Title]: {reg.get('title')}")
    print(f"[Date]: {reg.get('publication_date')}")
    print(f"[Source]: {reg.get('source_url')}")
    print(f"[Text Snippet]: {reg.get('full_text', '')[:150]}...\n")

if __name__ == "__main__":
    # Example 1: Run the automated monitoring loop
    run_monitoring_cycle()

    # Example 2: Manually extract a specific page
    extract_specific_regulation()