import struct
import time

class ACFClient:
    def __init__(self, pipe_path=r'\\.\pipe\acf_security_pipe'):
        self.pipe_path = pipe_path

    def validate_prompt(self, prompt: str):
        start = time.perf_counter()
        try:
            # 1. Open the Pipe created by your Go Sidecar
            with open(self.pipe_path, 'r+b', buffering=0) as f:
                # 2. Send the prompt to Go
                f.write(prompt.encode('utf-8'))
                
                # 3. Read the 2-byte uint16 result
                result_bytes = f.read(2)
                if not result_bytes:
                    return "ERROR: No response"
                
                # Unpack the bitmask (Little Endian)
                mask = struct.unpack('<H', result_bytes)[0]
                latency = (time.perf_counter() - start) * 1000
                
                return {"mask": bin(mask), "latency_ms": round(latency, 2), "raw_mask": mask}
        except FileNotFoundError:
            return "ERROR: Sidecar not running. Start sidecar.exe first."