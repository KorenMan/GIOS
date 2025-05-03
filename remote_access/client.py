import socket
import threading
import json
import base64
import os
import time
import sys
import io
from pynput import keyboard
from PIL import Image, ImageTk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import ttk

class Client:
    def __init__(self, server_host='127.0.0.1', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.server_public_key = None
        self.aes_key = None
        self.connected = False
        self.keyboard_listener = None
        self.pressed_keys = set() # Keep track of pressed keys

        # Screen sharing
        self.receiving_screenshot = False
        self.screenshot_chunks = []
        self.expected_chunks = 0

        # GUI elements
        self.root = None
        self.screenshot_label = None
        self.screenshot_frame = None
        self.current_screenshot = None
        self.screenshot_canvas = None
        self.screenshot_inner_frame = None

    def start_gui(self):
        """Initialize the GUI"""
        self.root = tk.Tk()
        self.root.title(f"Remote Control - {self.server_host}:{self.server_port}")
        self.root.geometry("1024x768")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Create frames
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)

        self.screenshot_frame = ttk.Frame(self.root)
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True)

        # Console/log frame
        log_frame = ttk.Frame(self.root, padding=5)
        log_frame.pack(fill=tk.X)

        log_label = ttk.Label(log_frame, text="Console:")
        log_label.pack(side=tk.LEFT, padx=5)

        # Connection status
        status_label = ttk.Label(control_frame, text="Status:")
        status_label.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="Disconnected")
        status_value = ttk.Label(control_frame, textvariable=self.status_var)
        status_value.pack(side=tk.LEFT, padx=5)

        # Connect button
        self.connect_button = ttk.Button(control_frame, text="Connect", command=self.toggle_connection)
        self.connect_button.pack(side=tk.LEFT, padx=5)

        # Screen sharing controls
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        screen_label = ttk.Label(control_frame, text="Screen Sharing:")
        screen_label.pack(side=tk.LEFT, padx=5)

        self.screen_button = ttk.Button(control_frame, text="Start", command=self.toggle_screen_sharing)
        self.screen_button.pack(side=tk.LEFT, padx=5)
        self.screen_button.config(state=tk.DISABLED)

        # FPS display
        self.fps_var = tk.StringVar(value="0 FPS")
        fps_label = ttk.Label(control_frame, textvariable=self.fps_var)
        fps_label.pack(side=tk.RIGHT, padx=5)

        # Console output area
        self.console_text = tk.Text(log_frame, height=6, wrap=tk.WORD)
        self.console_text.pack(fill=tk.X, expand=True, padx=5, pady=5)

        # Add scrollbar to console
        console_scrollbar = ttk.Scrollbar(self.console_text, command=self.console_text.yview)
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console_text.config(yscrollcommand=console_scrollbar.set)

        # Redirect print statements to the console
        self._redirect_stdout()

        # Screenshot display area with scrollbars
        screenshot_container = ttk.Frame(self.screenshot_frame)
        screenshot_container.pack(fill=tk.BOTH, expand=True)

        # Add scrollbars
        h_scrollbar = ttk.Scrollbar(screenshot_container, orient=tk.HORIZONTAL)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        v_scrollbar = ttk.Scrollbar(screenshot_container)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create canvas for scrolling
        self.screenshot_canvas = tk.Canvas(screenshot_container, bg='black')
        self.screenshot_canvas.pack(fill=tk.BOTH, expand=True)

        # Configure scrollbars
        h_scrollbar.config(command=self.screenshot_canvas.xview)
        v_scrollbar.config(command=self.screenshot_canvas.yview)
        self.screenshot_canvas.config(xscrollcommand=h_scrollbar.set, yscrollcommand=v_scrollbar.set)

        # Create frame inside canvas for the screenshot
        self.screenshot_inner_frame = ttk.Frame(self.screenshot_canvas)
        self.screenshot_canvas.create_window((0, 0), window=self.screenshot_inner_frame, anchor=tk.NW)

        # Screenshot label inside the inner frame
        self.screenshot_label = ttk.Label(self.screenshot_inner_frame)
        self.screenshot_label.pack()

        # Configure canvas scrolling
        self.screenshot_inner_frame.bind("<Configure>",
            lambda e: self.screenshot_canvas.configure(
                scrollregion=self.screenshot_canvas.bbox("all")
            )
        )

        # Set up screen sharing variables
        self.screen_sharing_active = False
        self.frames_received = 0
        self.last_fps_update = time.time()

        # Start the GUI main loop
        self.root.mainloop()

    def _redirect_stdout(self):
        """Redirect stdout to the console text widget"""
        class StdoutRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
                self.buffer = ""

            def write(self, string):
                self.buffer += string
                if '\n' in self.buffer:
                    lines = self.buffer.split('\n')
                    # Add all complete lines
                    for line in lines[:-1]:
                        self.text_widget.after(0, self._add_line, line + '\n')
                    # Keep the last incomplete line in the buffer
                    self.buffer = lines[-1]

            def _add_line(self, line):
                try:
                    self.text_widget.insert(tk.END, line)
                    self.text_widget.see(tk.END)
                except tk.TclError: # Handle cases where widget might be destroyed
                    pass

            def flush(self):
                if self.buffer:
                    self.text_widget.after(0, self._add_line, self.buffer)
                    self.buffer = ""

        # Redirect stdout to our custom handler
        sys.stdout = StdoutRedirector(self.console_text)
        sys.stderr = StdoutRedirector(self.console_text) # Also redirect stderr

    def on_closing(self):
        """Handle window closing"""
        print("[*] Closing application...")
        self.disconnect()
        if self.root:
            self.root.destroy()
        self.running = False # Ensure loops stop

    def toggle_connection(self):
        """Toggle connection to server"""
        if self.connected:
            self.disconnect()
        else:
            # Start the client connection in a separate thread
            self.running = True
            connection_thread = threading.Thread(target=self.connect)
            connection_thread.daemon = True
            connection_thread.start()

    def toggle_screen_sharing(self):
        """Toggle screen sharing"""
        if not self.connected:
            print("[!] Not connected to server.")
            return

        if self.screen_sharing_active:
            self.screen_sharing_active = False
            self.send_message('screen_control', {'action': 'stop'})
            self.screen_button.config(text="Start")
            print("[*] Screen sharing stopped.")
        else:
            self.screen_sharing_active = True
            # Set default quality and scale (optional, can be adjusted)
            self.send_message('screen_control', {'action': 'quality', 'value': 70})
            self.send_message('screen_control', {'action': 'scale', 'value': 0.75})
            self.send_message('screen_control', {'action': 'start'})
            self.screen_button.config(text="Stop")
            print("[*] Screen sharing started.")
            # Reset FPS counter
            self.frames_received = 0
            self.last_fps_update = time.time()

    def connect(self):
        """Connect to the server and establish encrypted communication"""
        try:
            # Create socket and connect
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10) # Add timeout for connection
            print(f"[*] Connecting to {self.server_host}:{self.server_port}...")
            self.client_socket.connect((self.server_host, self.server_port))
            self.client_socket.settimeout(None) # Remove timeout after connection
            print(f"[*] Connected to server at {self.server_host}:{self.server_port}")
            if self.root:
                self.status_var.set(f"Connected to {self.server_host}:{self.server_port}")
                self.connect_button.config(text="Disconnect")
                self.screen_button.config(state=tk.NORMAL)

            # Perform key exchange
            self._key_exchange()

            self.connected = True

            # Start listening for keyboard events (moved after connection and key exchange)
            self._start_keyboard_listener()

            # Start a thread to receive messages
            receiver_thread = threading.Thread(target=self._receive_messages)
            receiver_thread.daemon = True
            receiver_thread.start()

            # Keep the connection active check (optional, can be removed if receive handles disconnects)
            # while self.connected and self.running:
            #     time.sleep(0.5)

        except socket.timeout:
            print(f"[!] Connection timed out to {self.server_host}:{self.server_port}")
            if self.root: self.status_var.set("Connection timeout")
            self.disconnect() # Ensure cleanup
        except ConnectionRefusedError:
            print(f"[!] Connection refused by {self.server_host}:{self.server_port}")
            if self.root: self.status_var.set("Connection refused")
            self.disconnect() # Ensure cleanup
        except Exception as e:
            print(f"[!] Connection error: {e}")
            if self.root: self.status_var.set(f"Error: {str(e)[:50]}")
            self.disconnect() # Ensure cleanup

    def disconnect(self):
        """Disconnect from the server"""
        was_connected = self.connected
        self.connected = False
        self.screen_sharing_active = False

        if self.keyboard_listener:
            print("[*] Stopping keyboard listener...")
            self.keyboard_listener.stop()
            # Ensure the listener thread has joined
            # self.keyboard_listener.join() # Blocking, consider if needed
            self.keyboard_listener = None
            self.pressed_keys.clear() # Clear pressed keys on disconnect

        if self.client_socket:
            print("[*] Closing socket...")
            try:
                # Optionally send a disconnect message
                # self.send_message('disconnect', {})
                self.client_socket.shutdown(socket.SHUT_RDWR) # Graceful shutdown
                self.client_socket.close()
            except Exception as e:
                print(f"[!] Error closing socket: {e}")
            self.client_socket = None

        if was_connected: print("[*] Disconnected from server")

        if self.root:
            try:
                self.status_var.set("Disconnected")
                self.connect_button.config(text="Connect")
                self.screen_button.config(state=tk.DISABLED)
                self.screen_button.config(text="Start")
                # Clear the screenshot display
                self.screenshot_label.config(image=None)
                self.screenshot_label.image = None
                self.fps_var.set("0 FPS")
            except tk.TclError: # Handle cases where GUI might be closing
                 pass

    def _key_exchange(self):
        """Perform RSA key exchange and establish AES key"""
        try:
            # Receive server's public key
            print("[*] Receiving server public key...")
            server_public_key_bytes = self.client_socket.recv(4096)
            if not server_public_key_bytes:
                raise ConnectionError("Server disconnected during key exchange (public key)")
            self.server_public_key = RSA.import_key(server_public_key_bytes)
            print("[*] Server public key received.")

            # Generate a random AES key
            self.aes_key = get_random_bytes(32) # 256-bit key

            # Encrypt the AES key with the server's public key
            print("[*] Encrypting AES key...")
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)

            # Send the encrypted AES key to the server
            print("[*] Sending encrypted AES key...")
            self.client_socket.sendall(encrypted_aes_key)
            print("[*] Secure connection established.")
        except Exception as e:
            print(f"[!] Key exchange failed: {e}")
            raise # Re-raise the exception to be caught by connect()

    def _encrypt_aes(self, message_data):
        """Encrypt data using AES and prepare JSON package"""
        try:
            message_json = json.dumps(message_data)
            message_bytes = message_json.encode('utf-8')

            # Generate a random IV
            iv = get_random_bytes(16)

            # Create cipher and encrypt
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))

            # Prepare the message package
            encrypted_package = {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8')
            }
            # Convert to JSON string and encode
            return json.dumps(encrypted_package).encode('utf-8')
        except Exception as e:
            print(f"[!] AES encryption error: {e}")
            return None

    def _decrypt_aes(self, encrypted_data):
        """Decrypt AES encrypted JSON package"""
        try:
            # Parse the encrypted message
            package_str = encrypted_data.decode('utf-8')
            data_dict = json.loads(package_str)

            iv = base64.b64decode(data_dict['iv'])
            ciphertext = base64.b64decode(data_dict['ciphertext'])

            # Create cipher and decrypt
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)

            # Unpad and decode
            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json) # Return the original dict/list
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            print(f"[!] AES decryption/parsing error: {e}")
            print(f"Received raw data snippet: {encrypted_data[:100]}...")
            return None # Indicate failure
        except Exception as e:
            print(f"[!] Unexpected AES decryption error: {e}")
            return None

    def send_message(self, msg_type, payload):
        """Encrypt and send a message to the server"""
        if not self.connected or not self.client_socket:
            print("[!] Cannot send message: Not connected.")
            return False
        try:
            message_data = {'type': msg_type, **payload} # Combine type and payload
            encrypted_message = self._encrypt_aes(message_data)
            if encrypted_message:
                # Add length prefix (4 bytes, big-endian)
                msg_len = len(encrypted_message)
                len_prefix = msg_len.to_bytes(4, byteorder='big')
                self.client_socket.sendall(len_prefix + encrypted_message)
                # print(f"[*] Sent: {msg_type}, len={msg_len}") # Debug
                return True
            else:
                print(f"[!] Failed to encrypt message of type {msg_type}")
                return False
        except socket.error as e:
            print(f"[!] Socket error sending message: {e}")
            self.disconnect()
            return False
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            return False

    def _receive_messages(self):
        """Receive and process messages from the server"""
        buffer = b""
        payload_len = -1

        while self.connected and self.client_socket and self.running:
            try:
                # Receive data from the socket
                data = self.client_socket.recv(4096) # Read up to 4KB
                if not data:
                    print("[!] Connection closed by server (received empty data).")
                    self.disconnect()
                    break
                buffer += data

                # Process buffer - loop to handle multiple messages in one recv
                while True:
                    if payload_len == -1: # Waiting for length prefix
                        if len(buffer) >= 4:
                            payload_len = int.from_bytes(buffer[:4], byteorder='big')
                            buffer = buffer[4:]
                            # print(f"[*] Expecting payload len: {payload_len}") # Debug
                        else:
                            break # Need more data for length

                    if payload_len != -1 and len(buffer) >= payload_len: # Have complete message
                        # Extract message payload
                        payload_data = buffer[:payload_len]
                        buffer = buffer[payload_len:]
                        payload_len = -1 # Reset for next message

                        # Decrypt and process the message
                        message = self._decrypt_aes(payload_data)
                        if message:
                            self._handle_message(message)
                        else:
                            print("[!] Failed to decrypt or parse message, skipping.")
                    else:
                        break # Need more data for payload

            except socket.timeout:
                # This shouldn't happen if timeout is None, but handle defensively
                print("[!] Socket timeout during receive (should not happen).")
                time.sleep(0.1)
                continue
            except socket.error as e:
                print(f"[!] Socket error receiving message: {e}")
                self.disconnect()
                break # Exit loop on socket error
            except Exception as e:
                print(f"[!] Error receiving or processing message: {e}")
                # Consider whether to disconnect or try to continue
                # For now, let's disconnect on unknown errors
                self.disconnect()
                break # Exit loop

        print("[*] Receiver thread finished.")


    def _handle_message(self, message):
        """Handle different types of messages received from the server"""
        msg_type = message.get('type')
        # print(f"[*] Received message type: {msg_type}") # Debug

        if msg_type == 'screenshot':
            img_data = message.get('data')
            if img_data:
                try:
                    img_bytes = base64.b64decode(img_data)
                    # Process in GUI thread
                    self.root.after(0, self._display_screenshot, img_bytes)
                    # Calculate FPS
                    self.frames_received += 1
                    now = time.time()
                    elapsed = now - self.last_fps_update
                    if elapsed >= 1.0:
                        fps = self.frames_received / elapsed
                        self.fps_var.set(f"{fps:.1f} FPS")
                        self.last_fps_update = now
                        self.frames_received = 0
                except (TypeError, ValueError, base64.binascii.Error) as e:
                    print(f"[!] Error decoding screenshot data: {e}")
                except Exception as e:
                     print(f"[!] Error displaying screenshot: {e}")
            else:
                print("[!] Received screenshot message with no data.")

        elif msg_type == 'server_message':
            content = message.get('content', 'No content')
            print(f"[Server]: {content}") # Print server messages to console

        elif msg_type == 'error':
             error_msg = message.get('message', 'Unknown server error')
             print(f"[!] Server Error: {error_msg}")

        else:
            print(f"[?] Received unknown message type: {msg_type}")


    def _display_screenshot(self, img_bytes):
        """Update the screenshot label with the new image"""
        if not self.root or not self.screenshot_label:
             return # Exit if GUI elements are gone

        try:
            img = Image.open(io.BytesIO(img_bytes))
            # Keep a reference to avoid garbage collection!
            self.current_screenshot = ImageTk.PhotoImage(img)
            self.screenshot_label.config(image=self.current_screenshot)

            # Update scroll region after image is loaded
            self.screenshot_label.update_idletasks() # Ensure label size is updated
            self.screenshot_canvas.configure(scrollregion=self.screenshot_canvas.bbox("all"))

        except Exception as e:
            print(f"[!] Error displaying screenshot in Tkinter: {e}")
            # Optionally clear the image on error
            # self.screenshot_label.config(image=None)
            # self.current_screenshot = None

    def _start_keyboard_listener(self):
        """Start the pynput keyboard listener"""
        if self.keyboard_listener:
            print("[!] Keyboard listener already running.")
            return

        # Define press and release handlers within the method scope
        def on_press(key):
            if not self.connected: # Stop sending if disconnected
                 return
            try:
                # Determine key identifier (char vs special)
                if hasattr(key, 'char') and key.char:
                    key_id = key.char
                    key_type = 'char'
                else:
                    # Use key.name if available (newer pynput), fallback to str
                    key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                    key_id = key_name
                    key_type = 'special'

                # Send 'key_down' only if not already pressed
                unique_key_repr = f"{key_type}:{key_id}"
                if unique_key_repr not in self.pressed_keys:
                    self.pressed_keys.add(unique_key_repr)
                    # print(f"[*] Key pressed: {unique_key_repr}") # Debug
                    self.send_message('key_event', {'key': key_id, 'key_kind': key_type, 'state': 'down'})

            except Exception as e:
                print(f"[!] Error handling key press: {e}")

        def on_release(key):
            if not self.connected: # Stop sending if disconnected
                # Stop the listener if it's still running after disconnect
                if self.keyboard_listener:
                     return False # Returning False stops the listener
                return

            try:
                # Determine key identifier
                if hasattr(key, 'char') and key.char:
                    key_id = key.char
                    key_type = 'char'
                else:
                    key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                    key_id = key_name
                    key_type = 'special'

                unique_key_repr = f"{key_type}:{key_id}"
                # Send 'key_up' and remove from pressed set
                if unique_key_repr in self.pressed_keys:
                    self.pressed_keys.remove(unique_key_repr)
                    # print(f"[*] Key released: {unique_key_repr}") # Debug
                    self.send_message('key_event', {'key': key_id, 'key_kind': key_type, 'state': 'up'})
                # else:
                    # Key released that wasn't tracked as pressed (can happen on startup/focus loss)
                    # Optionally send 'up' anyway? Depends on desired behavior.
                    # self.send_message('key_event', {'key': key_id, 'type': key_type, 'state': 'up'})

            except Exception as e:
                print(f"[!] Error handling key release: {e}")

        # Start the keyboard listener in a separate thread
        # Use suppress=False to allow key events to pass through to other apps
        self.keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release, suppress=False)
        self.keyboard_listener.daemon = True # Ensure thread exits when main program exits
        self.keyboard_listener.start()
        print("[*] Keyboard listener started.")

    # Removed send_text and send_key as direct methods, use send_message now


if __name__ == "__main__":
    # Parse command line arguments
    server_host = '127.0.0.1'
    server_port = 5555

    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            server_port = int(sys.argv[2])
        except ValueError:
            print(f"Invalid port number: {sys.argv[2]}. Using default {server_port}.")

    print(f"Attempting to connect to {server_host}:{server_port}")
    client = Client(server_host=server_host, server_port=server_port)
    client.start_gui() # Start the GUI, connection attempt happens via button/thread