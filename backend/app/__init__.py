"""JASUSI backend package.

The URL feature extractor lives in `ml/features/` and is shared by training and
inference (same function in both, by design). The repo root is put on the import
path here so `import ml.features...` works however the server is started.
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.append(_REPO_ROOT)
