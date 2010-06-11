
from jpake import JPAKE, JPAKEError, params_80, params_112, params_128
from jpake import DuplicateSignerID, BadZeroKnowledgeProof, GX4MustNotBeOne
_hush_pyflakes = [JPAKE, JPAKEError, params_80, params_112, params_128,
                  DuplicateSignerID, BadZeroKnowledgeProof, GX4MustNotBeOne]
del _hush_pyflakes

try:
    from _version import __version__ as v
    __version__ = v
    del v
except ImportError:
    __version__ = "UNKNOWN"

