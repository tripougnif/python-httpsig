from pkg_resources import get_distribution, DistributionNotFound

from .sign import Signer, HeaderSigner
from .verify import Verifier, HeaderVerifier
from .sign_algorithms import *

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    # package is not installed
    pass

__all__ = (Signer, HeaderSigner, Verifier, HeaderVerifier)
