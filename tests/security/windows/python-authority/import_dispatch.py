"""Only the genuine CPython import/exception boundary; authority operations live in Rust."""
import sys

_authority_error = None
try:
    _authority_phase = 'import-ctypes'
    import ctypes
    _authority_phase = 'import-ctypes-wintypes'
    import ctypes.wintypes as w
    _authority_phase = 'import-json'
    import json
    _authority_phase = 'import-os'
    import os
    _authority_phase = 'import-pathlib'
    from pathlib import Path
    _authority_phase = 'import-runpy'
    import runpy
    _authority_phase = 'import-subprocess'
    import subprocess
    _authority_phase = 'import-time'
    import time
except Exception as _caught:
    _authority_error = _caught

# The owned core is deliberately loaded only after the real imports or their
# actual exception. Failure to load it cannot produce qualified authority wire.
import _registry_authority
raise SystemExit(_registry_authority.dispatch(globals(), _authority_phase, _authority_error))
