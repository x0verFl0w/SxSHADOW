"""
Tool renamed to SxSHADOW.  This shim preserves backwards compatibility.
Use: python sxshadow.py  (preferred)
     python wraith.py    (alias, same behaviour)
"""
from sxshadow import main
import sys
sys.exit(main())
