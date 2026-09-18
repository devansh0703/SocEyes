"""Unit tests for the app.

Run them from the repository root:

    python -m unittest discover -s tests -v      # or: make test
"""

import os
import tempfile

# Every test module must point the state root at a scratch directory *before*
# importing application modules: several of them resolve state paths at import
# time, and none of them should ever touch a real deployment's state.
os.environ.setdefault("FDA_STATE_DIR", tempfile.mkdtemp(prefix="fda-tests-state-"))