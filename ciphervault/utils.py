import secrets
import string
import threading
import time
from typing import Optional

try:
    import pyperclip
except Exception:
    pyperclip = None

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def mask_password(pw: str, show: bool = False) -> str:
    return pw if show else '*' * min(len(pw), 8)

def copy_to_clipboard(text: str, timeout: int = 10) -> bool:
    """Copy text to clipboard and clear it after `timeout` seconds.
    Returns True on success, False if clipboard unavailable."""
    if not pyperclip:
        return False
    try:
        pyperclip.copy(text)
    except Exception:
        return False

    def clear_later(t: int):
        time.sleep(t)
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pass

    th = threading.Thread(target=clear_later, args=(timeout,), daemon=True)
    th.start()
    return True
