"""Password verification; the configured hash is not included in session cookies."""
import hashlib
import os
import secrets
from werkzeug.security import check_password_hash

def settings():
    hashed=os.environ.get('SEC_CHECKER_PASSWORD_HASH','')
    plain=os.environ.get('SEC_CHECKER_PASSWORD','')
    value=hashed or plain
    return hashed,plain,hashlib.sha256(value.encode()).hexdigest() if value else None

def verify(password):
    hashed,plain,_=settings()
    if hashed:
        try:return check_password_hash(hashed,password)
        except (ValueError,TypeError):return False
    return bool(plain) and secrets.compare_digest(password.encode(),plain.encode())
