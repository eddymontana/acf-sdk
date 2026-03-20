import struct
import functools
from typing import Callable

class ACFProtector:
    def __init__(self, pipe_path=r'\\.\pipe\acf_security_pipe'):
        self.pipe_path = pipe_path

    def _check(self, prompt: str) -> int:
        """Internal bridge to the Go Sidecar."""
        try:
            with open(self.pipe_path, 'r+b', buffering=0) as f:
                f.write(prompt.encode('utf-8'))
                res = f.read(2)
                return struct.unpack('<H', res)[0] if res else 0
        except Exception:
            return 0 # Fail open or closed based on policy; 0 = Pass

    def protect(self, func: Callable):
        """The Decorator: Just drop @guard.protect over any LLM function!"""
        @functools.wraps(func)
        def wrapper(prompt, *args, **kwargs):
            mask = self._check(prompt)
            
            # If Bit 2 (SQLi) or Bit 3 (Prompt Injection) are set, block it!
            if mask & 0b1100: 
                print(f"[ACF SHIELD] Blocked malicious prompt. Mask: {bin(mask)}")
                return "Security Error: Your prompt was flagged by the ACF Kernel."
            
            return func(prompt, *args, **kwargs)
        return wrapper