#!/bin/bash

# ==============================================================================
# ThreatLens - Automated Setup and Launch Script
# This script handles all prerequisites and starts the AI SOC Analyst dashboard.
# ==============================================================================

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}🛡️  ThreatLens Initialization Sequence Started     ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. System Packages Check for Python venv
echo -e "\n${YELLOW}[1/4] Checking Python Virtual Environment Support...${NC}"
if ! dpkg -s python3-venv >/dev/null 2>&1; then
    echo -e "${RED}Warning: python3-venv is not installed.${NC}"
    echo -e "Installing python3-venv (requires sudo)..."
    sudo apt-get update && sudo apt-get install -y python3-venv
else
    echo -e "${GREEN}python3-venv is already installed.${NC}"
fi

# 2. Virtual Environment Setup
echo -e "\n${YELLOW}[2/4] Setting up Python Virtual Environment...${NC}"
if [ ! -d "venv" ]; then
    echo "Creating new virtual environment..."
    python3 -m venv venv
else
    echo -e "${GREEN}Virtual environment already exists.${NC}"
fi

echo "Activating virtual environment..."
source venv/bin/activate

# 3. Install Python Dependencies
echo -e "\n${YELLOW}[3/4] Installing Python Dependencies...${NC}"
pip install -r requirements.txt

# 4. Ollama Verification
echo -e "\n${YELLOW}[4/4] Verifying Ollama AI Engine...${NC}"
if ! command -v ollama &> /dev/null; then
    echo -e "${RED}Ollama is not installed. Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    echo -e "${GREEN}Ollama installed successfully.${NC}"
else
    echo -e "${GREEN}Ollama is already installed.${NC}"
fi

# Start the Ollama background service if it's not already running
if ! systemctl is-active --quiet ollama; then
    echo "Starting Ollama service..."
    sudo systemctl start ollama || {
        echo -e "${YELLOW}Could not start via systemctl, attempting background process...${NC}"
        ollama serve > /dev/null 2>&1 &
    }
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}✅ Setup Complete! Launching ThreatLens Dashboard...${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "Note: If the AI model (llama3.1:8b) is missing, the dashboard will prompt you to download it."

# 5. Launch Application
exec streamlit run app.py
