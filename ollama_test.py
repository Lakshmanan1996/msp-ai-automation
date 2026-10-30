import json
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

prompt = """
You are an MSP/NOC server investigator.

A Windows server generated a "Server Offline" alert.

The following evidence was collected:

- Hostname matches the alert: TRUE
- Default gateway reachable: TRUE
- DNS working: TRUE
- TCP 443 working: TRUE
- Relevant Windows events found: FALSE
- Infrastructure type: UNKNOWN

Analyze the evidence.

Do not assume the offline alert is correct.
Do not invent missing evidence.
Explain whether the current evidence justifies remediation.
"""

payload = {
    "model": "qwen2.5:7b",
    "prompt": prompt,
    "stream": False
}

data = json.dumps(payload).encode("utf-8")

request = urllib.request.Request(
    OLLAMA_URL,
    data=data,
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(request) as response:
    result = json.loads(response.read().decode("utf-8"))

print("\n===== LOCAL AI RESPONSE =====\n")
print(result["response"])
