#!/bin/bash

# RegWatch - Startup Script
# This script activates the virtual environment and runs the Flask web app

echo "🚀 Starting RegWatch Web Application..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  Warning: .env file not found"
    echo "   The app will run but some features may not work without API keys"
    echo "   Edit .env file to add your API keys"
    echo ""
fi

# Set Flask environment variables
export FLASK_APP=web/app.py
export FLASK_ENV=development

# Run the Flask app
echo "✅ Virtual environment activated"
echo "🌐 Starting Flask server on http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 web/app.py
