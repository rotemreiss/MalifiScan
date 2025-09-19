#!/bin/bash
# Setup script for Security Scanner CLI testing

set -e

echo "🔧 Setting up Security Scanner CLI for testing..."

# Check if Python 3.8+ is available
python3 --version || { echo "❌ Python 3.8+ is required"; exit 1; }

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Make CLI executable
chmod +x cli.py

# Copy config files if they don't exist
if [ ! -f ".env" ]; then
    echo "📄 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your actual credentials!"
fi

echo ""
echo "✅ Setup complete! You can now use the CLI:"
echo ""
echo "📋 Quick Start Commands:"
echo "  source venv/bin/activate  # Activate virtual environment"
echo "  python cli.py health check         # Check if services are working"
echo "  python cli.py scan run            # Run a manual scan"
echo "  python cli.py jfrog search lodash npm  # Search for a package"
echo "  python cli.py logs view           # View recent scan results"
echo "  python cli.py interactive         # Start interactive mode"
echo ""
echo "📖 For more commands: python cli.py --help"
echo ""
echo "⚠️  IMPORTANT: Edit .env file with your JFrog credentials before testing!"