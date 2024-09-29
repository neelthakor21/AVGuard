from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import time



class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        filename = self.path
        file_name = os.path.basename(filename)

        new_directory = '/app/malware'
        os.chdir(new_directory)

        current_directory = os.getcwd()
        file_path = os.path.join(current_directory, file_name)

        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(f.read())
        else:
            self.send_error(404, 'File not found')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        uploaded_file = self.rfile.read(content_length)

        # headers, file_content = uploaded_file.split(b'\r\n\r\n', 1)
        
        # Get the filename from the 'Content-Disposition' header
        filename = self.get_filename()
        
        if not filename:
            self.send_error(400, "No filename provided")
            return

        decoded_file_content = uploaded_file.decode('utf-8')

        lines = decoded_file_content.split('\n')

        lines = lines[1:-2]

        filtered_lines = []

        for line in lines:
            if "Content-Disposition:" not in line:
                filtered_lines.append(line)

        filtered_content = '\n'.join(filtered_lines)

        filtered_content = filtered_content.encode('utf-8')

        
        # Save uploaded file to malware directory with the original filename
        with open(f'/app/malware/{filename}', 'wb') as file:
            file.write(filtered_content)
        
        # Send response
        self.send_response(200)
        self.end_headers()

    def get_filename(self):
        content_disposition = self.headers.get('Content-Disposition', '')
        if 'filename=' in content_disposition:
            params = content_disposition.split(';')
            # Iterate through the parameters to find the filename
            filename = None
            for param in params:
                if 'filename=' in param:
                    # Extract the filename value
                    filename = param.split('=')[1].strip('"')
            return filename

        else:
            # No filename found in the Content-Disposition header
            SERIES = time.time()
            default_filename = f"defaultFile_{SERIES}"
            return default_filename  # Provide a default filename if needed

def run_server():
    server_address = ("172.18.0.2", 9000)
    httpd = HTTPServer(server_address, RequestHandler)
    # print('Starting server...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
