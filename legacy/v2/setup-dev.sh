#!/bin/bash

echo "========================================"
echo "NRP Development Setup (Linux/Mac)"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 ist nicht installiert!"
    echo "Bitte installieren Sie Python 3.8 oder neuer."
    exit 1
fi

echo "Python gefunden:"
python3 --version
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Erstelle Virtual Environment..."
    python3 -m venv venv
    echo "Virtual Environment erstellt."
else
    echo "Virtual Environment existiert bereits."
fi
echo ""

# Activate virtual environment and install dependencies
echo "Aktiviere Virtual Environment und installiere Dependencies..."
source venv/bin/activate

echo "Installiere Dependencies..."
pip install --upgrade pip
pip install -e .

echo ""
echo "========================================"
echo "Setup abgeschlossen!"
echo "========================================"
echo ""
echo "Zum Aktivieren der Virtual Environment:"
echo "  source venv/bin/activate"
echo ""
echo "Zum Testen der Installation:"
echo "  nrp --help"
echo ""
