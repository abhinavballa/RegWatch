import os
import sys
import json
import logging

# --- Setup Path to Import Module ---
# Assuming the module is located in 'src/agents/analysis_agent.py' relative to this script
current_dir = os.path.dirname(os.path.abspath(__file__))
# Adjust this path based on your actual project structure
sys.path.append(os.path.join(current_dir, 'src', 'agents'))

try:
    import analysis_agent
except ImportError:
    # Fallback for flat directory structures
    try:
        import analysis_agent
    except ImportError:
        print("Error: Could not import 'analysis_agent'. Ensure it is in your Python path.")
        sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_example() -> None:
    """
    Demonstrates the usage of the analysis_agent module for RegWatch.
    """
    print("=== RegWatch Analysis Agent Example ===\n")

    # Ensure API Key is set (mocking it for this example if not present)
    if not os.getenv("TOOLHOUSE_API_KEY"):
        print("NOTE: TOOLHOUSE_API_KEY is not set. The agent will likely use mock logic or fail gracefully.\n")
        os.environ["TOOLHOUSE_API_KEY"] = "mock-key-for-example"

    # --- Scenario 1: Analyzing a Substantive Change ---
    print("1. Analyzing a substantive change to HIPAA encryption requirements...")
    
    old_text = (
        "164.312(a)(2)(iv): Implement a mechanism to encrypt and decrypt "
        "electronic protected health information."
    )
    
    new_text = (
        "164.312(a)(2)(iv): Implement a mechanism to encrypt and decrypt "
        "electronic protected health information using AES-256 standards at minimum."
    )
    
    reg_id = "HIPAA-164.312(a)(2)(iv)"

    # Call the main analysis function
    # This uses the LLM to determine severity, change type, and summary
    analysis_result = analysis_agent.analyze_change(old_text, new_text, reg_id)

    print("\n--- Analysis Result ---")
    print(f"Regulation ID: {analysis_result.get('regulation_id')}")
    print(f"Change Type:   {analysis_result.get('change_type')}")
    print(f"Severity:      {analysis_result.get('severity')}")
    print(f"Summary:       {analysis_result.get('summary')}")
    print(f"Impact Est.:   {analysis_result.get('customer_impact_estimate')}")
    
    print("\n--- Affected Checkers ---")
    # The agent automatically maps the regulation to specific code checkers
    for checker in analysis_result.get('affected_checkers', []):
        print(f" - {checker}")

    print("\n" + "="*40 + "\n")

    # --- Scenario 2: Mapping Checkers Manually ---
    print("2. Manually mapping a regulation ID to checkers...")
    
    # Sometimes we just want to know which checkers apply to a specific regulation ID
    # without performing a full text diff.
    target_reg = "164.312(b)" # Audit controls
    summary_context = "Updates to audit logging retention periods."
    
    checkers = analysis_agent.map_to_checkers(target_reg, summary_context)
    
    print(f"Regulation: {target_reg}")
    print(f"Context:    {summary_context}")
    print(f"Mapped Checkers: {checkers}")

    print("\n" + "="*40 + "\n")

    # --- Scenario 3: Handling No Changes ---
    print("3. Analyzing identical text (No Change)...")
    
    text = "Covered entities must ensure confidentiality."
    no_change_result = analysis_agent.analyze_change(text, text, "HIPAA-General")
    
    print(f"Change Type: {no_change_result.get('change_type')}")
    print(f"Severity:    {no_change_result.get('severity')}")

if __name__ == "__main__":
    run_example()