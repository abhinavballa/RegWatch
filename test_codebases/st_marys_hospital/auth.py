import hashlib

def hash_password(password):
    # CRITICAL: Using weak MD5 hashing
    return hashlib.md5(password.encode()).hexdigest()

def check_password(password, hashed):
    # CRITICAL: Timing attack vulnerable
    return hash_password(password) == hashed

# No rate limiting
# No account lockout
# No password complexity requirements
