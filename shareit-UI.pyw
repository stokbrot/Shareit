import socket
import hashlib
import os
import struct
import sys
import time
import threading
from tkinter import Tk, ttk, Frame, Label, Entry, Button, Text, filedialog, messagebox, scrolledtext
import requests

CHUNK_SIZE = 10  * 1024 * 1024  # 10 MB
DEFAULT_PORT = 5001
MAX_RETRIES = 100

def get_public_ip():
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json()['ip']
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None

class FileTransferApp:
    def __init__(self, root):
        self.root = root 
        self.root.title("File Transfer")
        self.root.geometry("600x500")
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_receiver_tab()
        self.create_sender_tab()
        
        
        
        # Console output
        self.console = scrolledtext.ScrolledText(root, height=10)
        self.console.pack(fill='both', expand=True)
        sys.stdout = TextRedirector(self.console, "stdout")
        
    
    
    
            
    def update_public_ip(self):
        ip = get_public_ip()  # Use one of the IP fetching methods from earlier
        self.ip_display.config(state='normal')
        self.ip_display.delete(0, 'end')
        self.ip_display.insert(0, ip if ip else "Not available")
        self.ip_display.config(state='readonly')
        
        # Select the text automatically for easy copying
        self.ip_display.selection_range(0, 'end')
        self.ip_display.icursor(0)  # Move cursor to start
    
    def create_receiver_tab(self):
        self.receiver_tab = Frame(self.notebook)
        self.notebook.add(self.receiver_tab, text="Receiver")
        
        # Port input
        Label(self.receiver_tab, text="Port:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.receiver_port = Entry(self.receiver_tab)
        self.receiver_port.insert(0, str(DEFAULT_PORT))
        self.receiver_port.grid(row=0, column=1, padx=5, pady=5, sticky='we')
        
        
        
        # Output directory
        Label(self.receiver_tab, text="Output Directory:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.output_dir = Entry(self.receiver_tab)
        self.output_dir.insert(0, os.path.dirname(os.path.abspath(__file__)))
        self.output_dir.grid(row=1, column=1, padx=5, pady=5, sticky='we')
        
        # ip stuff
        Label(self.receiver_tab, text="Your Public IP:").grid(row=4, column=0, padx=5, pady=5, sticky='e')
        
        self.ip_display = Entry(self.receiver_tab, state='readonly', font=('Arial', 10), 
                            relief='sunken', width=20)
        self.ip_display.grid(row=4, column=1, padx=5, pady=5, sticky='we')
        
        self.ip_refresh = Button(self.receiver_tab, text="↻", width=2,
                            command=self.update_public_ip)
        self.ip_refresh.grid(row=4, column=2, padx=5, pady=5)
        
        # Initial update
        self.update_public_ip()
        
        
        # Browse button for directory
        Button(self.receiver_tab, text="Browse", command=self.browse_output_dir).grid(row=1, column=2, padx=5, pady=5)
        
        # Start button
        Button(self.receiver_tab, text="Start Receiver", command=self.start_receiver).grid(row=2, column=0, columnspan=3, pady=10)
        
        # Progress
        self.receiver_progress = ttk.Progressbar(self.receiver_tab, orient='horizontal', length=400, mode='determinate')
        self.receiver_progress.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky='we')
        
    def create_sender_tab(self):
        self.sender_tab = Frame(self.notebook)
        self.notebook.add(self.sender_tab, text="Sender")
        
        # Host input
        Label(self.sender_tab, text="Receiver IP:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.sender_host = Entry(self.sender_tab)
        self.sender_host.insert(0, "127.0.0.1")
        self.sender_host.grid(row=0, column=1, padx=5, pady=5, sticky='we')
        
        # Port input
        Label(self.sender_tab, text="Port:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.sender_port = Entry(self.sender_tab)
        self.sender_port.insert(0, str(DEFAULT_PORT))
        self.sender_port.grid(row=1, column=1, padx=5, pady=5, sticky='we')
        
        # File selection
        Label(self.sender_tab, text="File to Send:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.file_path = Entry(self.sender_tab)
        self.file_path.grid(row=2, column=1, padx=5, pady=5, sticky='we')
        Button(self.sender_tab, text="Browse", command=self.browse_file).grid(row=2, column=2, padx=5, pady=5)
        
        # chunk size
        Label(self.sender_tab, text="Chunk Size (MB):").grid(row=3, column=0, padx=5, pady=5, sticky='e')
        self.chunk_size = Entry(self.sender_tab)
        self.chunk_size.insert(0, "10")  # Default 10 MB
        self.chunk_size.grid(row=3, column=1, padx=5, pady=5, sticky='we')
        
        # Start button
        Button(self.sender_tab, text="Start Sender", command=self.start_sender).grid(row=4, column=0, columnspan=3, pady=10)
        
        # Progress
        self.sender_progress = ttk.Progressbar(self.sender_tab, orient='horizontal', length=400, mode='determinate')
        self.sender_progress.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky='we')
    
    def browse_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir.delete(0, 'end')
            self.output_dir.insert(0, dir_path)
    
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.delete(0, 'end')
            self.file_path.insert(0, file_path)
    
    def start_receiver(self):
        port = int(self.receiver_port.get())
        output_dir = self.output_dir.get()
        
        thread = threading.Thread(target=self.run_receiver, args=(port, output_dir), daemon=True)
        thread.start()
    
    def start_sender(self):
        host = self.sender_host.get()
        port = int(self.sender_port.get())
        file_path = self.file_path.get()
        
        try:
            chunk_size_mb = float(self.chunk_size.get())
            chunk_size = int(chunk_size_mb * 1024 * 1024)  # Convert MB to bytes
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for chunk size")
            return
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file to send")
            return
        
        thread = threading.Thread(target=self.run_sender, args=(host, port, file_path, chunk_size), daemon=True)
        thread.start()
    
    def sha256(self, data):
        return hashlib.sha256(data).digest()
    
    def update_receiver_progress(self, value, max_value):
        percent = (value / max_value) * 100
        self.receiver_progress['value'] = percent
        self.root.update_idletasks()
    
    def update_sender_progress(self, value, max_value):
        percent = (value / max_value) * 100
        self.sender_progress['value'] = percent
        self.root.update_idletasks()
    
    def run_receiver(self, port, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        print(f"[Receiver] Ready to receive files in directory: {os.path.abspath(output_dir)}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            s.listen(1)
            print(f"[Receiver] Listening on port {port}")
            conn, addr = s.accept()
            print(f"[Receiver] Connected by {addr}")

            # Receive metadata (size, name, chunk_size)
            metadata = conn.recv(1024)
            file_size, file_name, sender_chunk_size = struct.unpack("!Q256sI", metadata)
            file_name = file_name.decode('utf-8').strip('\x00')
            conn.sendall(b'OK_META')

            output_path = os.path.join(output_dir, file_name)
            print(f"[Receiver] Receiving {file_name} ({file_size:,} bytes), chunk size: {sender_chunk_size:,}")

            with open(output_path, 'wb') as outfile:
                expected_chunk = 0
                total_received = 0
                while total_received < file_size:
                    header = conn.recv(8)
                    if not header:
                        print("\n[Receiver] Connection closed by sender.")
                        break

                    try:
                        chunk_index, chunk_len = struct.unpack("!II", header)
                    except struct.error:
                        print("\n[Receiver] Invalid header received.")
                        break

                    data = b''
                    while len(data) < chunk_len:
                        packet = conn.recv(min(chunk_len - len(data), sender_chunk_size))
                        if not packet:
                            print(f"\n[Receiver] Incomplete chunk {chunk_index}")
                            break
                        data += packet

                    received_hash = conn.recv(32)
                    actual_hash = self.sha256(data)

                    if received_hash != actual_hash:
                        print(f"\n[Receiver] Chunk {chunk_index} hash mismatch! Asking for resend.")
                        conn.sendall(b'RETRY')
                        continue
                    else:
                        if chunk_index == expected_chunk:
                            outfile.write(data)
                            outfile.flush()
                            os.fsync(outfile.fileno())
                            total_received += len(data)
                            self.update_receiver_progress(total_received, file_size)
                            expected_chunk += 1
                            conn.sendall(b'OK')
                        else:
                            print(f"\n[Receiver] Unexpected chunk index {chunk_index}, expected {expected_chunk}.")
                            conn.sendall(b'RETRY')

            print(f"\n[Receiver] File received successfully: {output_path}")
            self.receiver_progress['value'] = 0
    
    def run_sender(self, host, port, file_path, chunk_size=CHUNK_SIZE):
        if not os.path.exists(file_path):
            print("Error: File not found!")
            return

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        bytes_sent_total = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            print(f"[Sender] Connected to {host}:{port}")

            # First send the file metadata (size and name)
            #metadata = struct.pack("!Q256s", file_size, file_name.encode('utf-8'))
            metadata = struct.pack("!Q256sI", file_size, file_name.encode('utf-8'), chunk_size)
            s.sendall(metadata)
            response = s.recv(16)
            if response != b'OK_META':
                print("[Sender] Failed to send file metadata")
                return

            print(f"[Sender] Sending file: {file_name} ({file_size:,} bytes)")

            with open(file_path, 'rb') as f:
                chunk_index = 0
                while bytes_sent_total < file_size:
                    data = f.read(chunk_size)
                    if not data:
                        break

                    digest = self.sha256(data)
                    header = struct.pack("!II", chunk_index, len(data))

                    retries = 0
                    while retries < MAX_RETRIES:
                        try:
                            s.sendall(header + data + digest)
                            response = s.recv(16)

                            if response == b'OK':
                                bytes_sent_total += len(data)
                                percent = (bytes_sent_total / file_size) * 100
                                self.update_sender_progress(bytes_sent_total, file_size)
                                chunk_index += 1
                                break
                            elif response == b'RETRY':
                                retries += 1
                                print(f"\n[Sender] Chunk {chunk_index} failed, retrying ({retries}/{MAX_RETRIES})...")
                                time.sleep(0.2)
                            else:
                                print(f"\n[Sender] Unexpected response: {response}")
                                break
                        except ConnectionError as e:
                            print(f"\n[Sender] Connection error: {e}")
                            retries += 1
                            time.sleep(1)
                    else:
                        print(f"\n[Sender] Chunk {chunk_index} failed after {MAX_RETRIES} retries. Aborting.")
                        break

            print("\n[Sender] File transfer complete.")
            self.sender_progress['value'] = 0

class TextRedirector(object):
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag

    def write(self, str):
        self.widget.configure(state="normal")
        self.widget.insert("end", str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see("end")
        self.widget.update_idletasks()

    def flush(self):
        pass

if __name__ == "__main__":
    root = Tk()
    app = FileTransferApp(root)
    root.mainloop()