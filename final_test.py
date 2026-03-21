import os
import time

PIPE_NAME = r"\\.\pipe\acf_security_pipe"

def test_connection():
    print(f"[*] Attempting to connect to ACF Kernel at {PIPE_NAME}...")
    try:
        # On Windows, Named Pipes can be opened like files
        with open(PIPE_NAME, 'r+b', buffering=0) as pipe:
            print("[+] SUCCESS: Connected to ACF Kernel!")

            # Send a dummy test string (This proves the pipe works)
            pipe.write(b"PING")
            print("[*] Sent PING to Kernel.")

    except FileNotFoundError:
        print("❌ ERROR: Named Pipe not found. Is the Go Sidecar still running?")
    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    test_connection()