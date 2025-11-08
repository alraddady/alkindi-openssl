from typing import Final

from alkindi import _liboqs

ffi = _liboqs.ffi
liboqs = _liboqs.lib

OQS_SUCCESS: Final[int] = 0
OQS_ERROR: Final[int] = -1
