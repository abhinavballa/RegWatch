#!/bin/bash
# RegWatch - Run Script
# Activates virtual environment and starts the Flask server

# Activate virtual environment
source venv/bin/activate

# Run the Flask app
python -m web.app
