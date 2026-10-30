from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import json
import uuid

class Fake8x8Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        print(
            f"\n[{datetime.now().isoformat(timespec='seconds')}] "
            f"POST {self.path}",
            flush=True,
        )
        print(f"Request body: {body}", flush=True)

        response = {
            "umid": "fake-" + str(uuid.uuid4()),
            "sessionStatus": "CREATED",
            "statusCode": 0,
            "statusMessage": "Fake call created (dummy 8x8)",
        }

        data = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass

server = HTTPServer(("127.0.0.1", 18080), Fake8x8Handler)
print("Fake 8x8 API listening on 127.0.0.1:18080", flush=True)

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("Stopping fake 8x8 API", flush=True)
finally:
    server.server_close()
