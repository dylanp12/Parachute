#!/usr/bin/env python3
"""Local test agent HTTP server for end-to-end testing."""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'agent': 'test-agent'}).encode())
        elif self.path == '/echo':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'method': 'GET',
                'path': self.path,
                'headers': dict(self.headers)
            }).encode())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'not found'}).encode())

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len)
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {'raw': body.decode('utf-8', errors='replace')}

        if self.path == '/execute':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'received': data,
                'status': 'executed',
                'path': self.path
            }).encode())
        elif self.path == '/tool_call':
            # Simulate a tool call response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'tool_result': data,
                'status': 'success'
            }).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'method': 'POST',
                'path': self.path,
                'body': data,
                'headers': dict(self.headers)
            }).encode())

    def log_message(self, format, *args):
        print(f"[AGENT] {args[0]} {args[1]} {args[2]}")


if __name__ == '__main__':
    port = 3000
    print(f"Test agent starting on port {port}...")
    HTTPServer(('0.0.0.0', port), Handler).serve_forever()
