#!/bin/bash

# Enumeraga MCP Server Setup Script (Python)

set -e

echo "Setting up Enumeraga MCP Server (Python)..."

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.10+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Python version: $PYTHON_VERSION"

# Check Python version (needs 3.10+)
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo "Error: Python 3.10+ required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment (recommended)
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install package in editable mode
echo "Installing MCP server package..."
pip install -e .

echo ""
echo "✓ Setup complete!"
echo ""
echo "To use the server:"
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Add to your Claude Desktop config:"
echo ""
cat << EOF
{
  "mcpServers": {
    "enumeraga": {
      "command": "python3",
      "args": ["$(pwd)/mcp_server_enumeraga/server.py"]
    }
  }
}
EOF
echo ""
echo "Config file location:"
echo "  macOS: ~/Library/Application Support/Claude/claude_desktop_config.json"
echo "  Windows: %APPDATA%\\Claude\\claude_desktop_config.json"
echo "  Linux: ~/.config/Claude/claude_desktop_config.json"
echo ""
echo "Or run directly:"
echo "  python3 mcp_server_enumeraga/server.py"
