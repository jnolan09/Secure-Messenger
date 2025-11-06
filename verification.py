# verification.py
# Handles Integrity, Authtentication and Non-Repudation
# Joshua Nolan

import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from cryptography.exceptions import InvalidSignature

# Security configuration constraints
HASH_ALGORITHM = "SHA-256"
SIGNATURE_KEY_SIZE = 2048
SIGNATURE_ALGORITHM = "RSA"
PADDING_SCENE = "PSS"
MAX_MESSAGE_AGE_MINUTES = 60
