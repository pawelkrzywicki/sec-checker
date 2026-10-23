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

# Cache only keyed digests of successfully verified credentials, never passwords.
# Every HTTP request still has to supply the username/password. Config changes
# change the cache key, and each worker bounds its cache to 256 entries / 60 sec.
import hmac
import threading
import time
_CACHE={}
_CACHE_LOCK=threading.Lock()

def verify_basic(username,password,pepper):
    expected_user=os.environ.get('SEC_CHECKER_USERNAME','reviewer')
    _,_,version=settings()
    if not version or not username or len(password)>1024 or len(username)>256:return False
    if not secrets.compare_digest(username.encode(),expected_user.encode()):return False
    key=hmac.new(pepper.encode(),(version+'\0'+username+'\0'+password).encode(),hashlib.sha256).digest()
    now=time.monotonic()
    with _CACHE_LOCK:
        if _CACHE.get(key,0)>now:return True
    if not verify(password):return False
    with _CACHE_LOCK:
        for expired in [x for x,until in _CACHE.items() if until<=now]:_CACHE.pop(expired,None)
        if len(_CACHE)>=256:_CACHE.pop(next(iter(_CACHE)))
        _CACHE[key]=now+60
    return True
