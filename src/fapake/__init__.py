"""Fuzzy asymmetric password-authenticated key exchange (fuzzy aPAKE)."""

from fapake.modmath import DEMO_GROUP, MODP_2048, Group
from fapake.protocol import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    AuthResult,
    ClientSession,
    Params,
    ProtocolError,
    ServerSession,
    UserRecord,
    authenticate_locally,
    register,
)

__all__ = [
    "DEFAULT_PARAMS",
    "DEMO_GROUP",
    "DEMO_PARAMS",
    "MODP_2048",
    "AuthResult",
    "ClientSession",
    "Group",
    "Params",
    "ProtocolError",
    "ServerSession",
    "UserRecord",
    "authenticate_locally",
    "register",
]
