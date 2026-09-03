"""Main entrypoint for AI Agent Hunting CLI."""
import sys
from pathlib import Path

# Automatically ensure src/ is in sys.path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from hunting.cli import main

if __name__ == "__main__":
    main()
