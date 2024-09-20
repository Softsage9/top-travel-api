from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent 

IMAGEDIR = BASE_DIR / "app/static/images"

# Ensure the directory exists
IMAGEDIR.mkdir(parents=True, exist_ok=True)
