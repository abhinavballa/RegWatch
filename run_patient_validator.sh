#!/bin/bash
# Wrapper script to run patient_data_validator_example.py with proper environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python -m venv "$VENV_DIR" --system-site-packages

    # Activate and install dependencies
    source "$VENV_DIR/bin/activate"
    pip install -q "pandera==0.18.0" "pandas==2.1.4" "multimethod<2"
else
    source "$VENV_DIR/bin/activate"
fi

# Run the example
python "$SCRIPT_DIR/examples/patient_data_validator_example.py"
