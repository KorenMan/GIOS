import socket
import threading
import json
import base64
import os
import time
import sys
import io
import queue
from pynput import keyboard
from PIL import Image, ImageTk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import ttk

# --- Protocol Constants ---
MSG_KEY = "KEY "
MSG_SCREEN = "SCRN"
MSG_CONTROL = "CTRL"
MSG_MSG = "MESG"
MSG_ERR = "ERR "
MSG_DISCONNECT = "BYE "
# Ensure codes are 4 bytes
HEADER_TYPE_LEN = 4
HEADER_SIZE_LEN = 8
# --- End Protocol Constants ---

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
        self.running = True # Flag to control threads

        # Screen sharing
        self.screen_sharing_active = False  # Track screen sharing state

        # Key event queue and processing thread
        self.key_event_queue = queue.Queue()
        self.key_processor_thread = None

        # GUI elements
        self.root = None
        self.screenshot_label = None
        self.screenshot_frame = None
        self.current_screenshot = None
        self.screenshot_canvas = None
        self.screenshot_inner_frame = None
        self.status_var = None
        self.connect_button = None
        self.screen_button = None
        self.keyboard_status_var = None
        self.fps_var = None
        self.console_text = None

        # FPS calculation
        self.frames_received = 0
        self.last_fps_update = time.time()


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

        # Keyboard status indicator
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        keyboard_label = ttk.Label(control_frame, text="Keyboard:")
        keyboard_label.pack(side=tk.LEFT, padx=5)

        self.keyboard_status_var = tk.StringVar(value="Disabled")
        self.keyboard_status = ttk.Label(control_frame, textvariable=self.keyboard_status_var)
        self.keyboard_status.pack(side=tk.LEFT, padx=5)

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
                    for line in lines[:-1]:
                        if self.text_widget.winfo_exists(): # Check if widget still exists
                            self.text_widget.after(0, self._add_line, line + '\n')
                    self.buffer = lines[-1]

            def _add_line(self, line):
                try:
                    if self.text_widget.winfo_exists():
                        self.text_widget.insert(tk.END, line)
                        self.text_widget.see(tk.END)
                except tk.TclError:
                    pass # Widget might be destroyed between check and insert

            def flush(self):
                if self.buffer and self.text_widget.winfo_exists():
                    self.text_widget.after(0, self._add_line, self.buffer)
                    self.buffer = ""

        sys.stdout = StdoutRedirector(self.console_text)
        sys.stderr = StdoutRedirector(self.console_text)

    def on_closing(self):
        """Handle window closing"""
        print("[*] Closing application...")
        self.running = False # Signal threads to stop
        self.disconnect()
        if self.root:
            self.root.destroy()


    def toggle_connection(self):
        """Toggle connection to server"""
        if self.connected:
            self.disconnect()
        else:
            self.connect()
            self.running = True

    def toggle_screen_sharing(self):
        """Toggle screen sharing"""
        if not self.connected:
            print("[!] Not connected to server.")
            return

        if self.screen_sharing_active:
            self._clear_keyboard_state() # Release keys on server
            self.send_message(MSG_CONTROL, {'action': 'stop'})
            self.screen_button.config(text="Start")
            self.keyboard_status_var.set("Disabled")
            print("[*] Screen sharing stopped. Keyboard control disabled.")
            self.screen_sharing_active = False
        else:
            self.screen_sharing_active = True
            self.send_message(MSG_CONTROL, {'action': 'quality', 'value': 70})
            self.send_message(MSG_CONTROL, {'action': 'scale', 'value': 0.75})
            self.send_message(MSG_CONTROL, {'action': 'start'})
            self.screen_button.config(text="Stop")
            self.keyboard_status_var.set("Enabled")
            print("[*] Screen sharing started. Keyboard control enabled.")
            self.frames_received = 0
            self.last_fps_update = time.time()
            self._clear_keyboard_state() # Ensure clean state locally

    def _clear_keyboard_state(self):
        """Reset keyboard state - release all pressed keys"""
        # Send key_up events for any keys still registered as pressed locally
        if self.connected and self.screen_sharing_active: # Only send if active
            for key_data in self.pressed_keys:
                try:
                    key_type, key_id = key_data.split(':', 1)
                    # Instead of direct network I/O, add to queue
                    self.key_event_queue.put(('up', key_id, key_type))
                except Exception as e:
                    print(f"[!] Error preparing key release {key_data}: {e}")

        # Clear the local set of pressed keys regardless of connection status
        self.pressed_keys.clear()
        print("[*] Local keyboard state cleared")

    def _process_key_events(self):
        """Thread function to process key events from the queue"""
        while self.running:
            try:
                # Get next event with timeout to allow checking running flag
                try:
                    event = self.key_event_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                # Extract event data
                state, key_id, key_type = event

                # Process the event
                if self.connected and self.screen_sharing_active:
                    self.send_message(MSG_KEY, {
                        'key': key_id,
                        'key_kind': key_type,
                        'state': state
                    })
                    # Small delay to prevent flooding the server
                    time.sleep(0.001)
                
                # Mark as done
                self.key_event_queue.task_done()
            
            except Exception as e:
                print(f"[!] Error processing key event: {e}")
                # Continue processing next event

        print("[*] Key processor thread terminated")

    def connect(self):
        """Connect to the server and establish encrypted communication"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            print(f"[*] Connecting to {self.server_host}:{self.server_port}...")
            self.client_socket.connect((self.server_host, self.server_port))
            self.client_socket.settimeout(None)
            print(f"[*] Connected to server at {self.server_host}:{self.server_port}")

            self._key_exchange() # Perform key exchange immediately after connect

            self.connected = True # Set connected only after successful key exchange

            # Start the key processor thread first
            self.key_processor_thread = threading.Thread(target=self._process_key_events, daemon=True)
            self.key_processor_thread.start()
            print("[*] Key event processor thread started")

            # Update GUI in main thread
            if self.root:
                self.root.after(0, self._update_gui_connected)

            self._start_keyboard_listener() # Start listener after connection

            receiver_thread = threading.Thread(target=self._receive_messages)
            receiver_thread.start()

        except socket.timeout:
            print(f"[!] Connection timed out to {self.server_host}:{self.server_port}")
            if self.root: self.root.after(0, self._update_gui_disconnected, "Connection timeout")
            self.disconnect()
        except ConnectionRefusedError:
            print(f"[!] Connection refused by {self.server_host}:{self.server_port}")
            if self.root: self.root.after(0, self._update_gui_disconnected, "Connection refused")
            self.disconnect()
        except Exception as e:
            print(f"[!] Connection error: {e}")
            if self.root: self.root.after(0, self._update_gui_disconnected, f"Error: {str(e)[:50]}")
            self.disconnect()

    def _update_gui_connected(self):
        """Update GUI elements for connected state (run in main thread)"""
        if not self.root or not self.status_var: return
        self.status_var.set(f"Connected to {self.server_host}:{self.server_port}")
        self.connect_button.config(text="Disconnect")
        self.screen_button.config(state=tk.NORMAL)

    def _update_gui_disconnected(self, reason="Disconnected"):
        """Update GUI elements for disconnected state (run in main thread)"""
        if not self.root or not self.status_var: return
        self.status_var.set(reason)
        self.connect_button.config(text="Connect")
        self.screen_button.config(state=tk.DISABLED)
        self.screen_button.config(text="Start")
        self.keyboard_status_var.set("Disabled")
        self.fps_var.set("0 FPS")
        # Clear screenshot display
        self.screenshot_label.config(image=None)
        self.current_screenshot = None # Clear reference


    def disconnect(self):
        """Disconnect from the server"""
        if not self.connected: # Prevent multiple disconnect calls
            return

        was_connected = self.connected
        self.connected = False
        self.screen_sharing_active = False

        # Send disconnect message if socket still exists
        if self.client_socket:
             try:
                 # Use the new send_message format (if key exists)
                 if self.aes_key:
                     self.send_message(MSG_DISCONNECT, {})
                 # Even if send fails, proceed with closing
             except Exception as e:
                 print(f"[!] Error sending disconnect message: {e}")

        # Stop keyboard listener first
        if self.keyboard_listener:
            print("[*] Stopping keyboard listener...")
            self.keyboard_listener.stop()
            self.keyboard_listener = None

        # Then clear local keyboard state (server state cleared by server on disconnect)
        self._clear_keyboard_state()

        # Close socket
        if self.client_socket:
            print("[*] Closing socket...")
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except Exception as e:
                print(f"[!] Error closing socket: {e}")
            self.client_socket = None

        self.aes_key = None # Clear AES key
        self.server_public_key = None

        if was_connected: print("[*] Disconnected from server")

        # Update GUI in main thread
        if self.root:
            self.root.after(0, self._update_gui_disconnected)


    def _key_exchange(self):
        """Perform RSA key exchange and establish AES key"""
        try:
            # Receive server's public key
            print("[*] Receiving server public key...")
            # Assume key is sent raw, adjust size if needed
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
            self.aes_key = None # Ensure key is None on failure
            raise # Re-raise the exception to be caught by connect()

    def _encrypt_aes(self, message_data):
        """Encrypts the payload dictionary using AES. Returns bytes."""
        if not self.aes_key:
            print("[!] AES key not available for encryption.")
            return None
        try:
            # The payload (message_data) should be a dictionary
            message_json = json.dumps(message_data)
            message_bytes = message_json.encode('utf-8')

            iv = get_random_bytes(16)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))

            # Combine IV and ciphertext (e.g., IV first)
            return iv + ct_bytes
        except Exception as e:
            print(f"[!] AES encryption error: {e}")
            return None

    def _decrypt_aes(self, encrypted_payload_bytes):
        """Decrypts the raw AES payload bytes (IV + ciphertext). Returns dictionary."""
        if not self.aes_key:
            print("[!] AES key not available for decryption.")
            return None
        try:
            if len(encrypted_payload_bytes) < 16: # Basic check for IV
                 print("[!] Decryption error: Payload too short.")
                 return None

            iv = encrypted_payload_bytes[:16]
            ciphertext = encrypted_payload_bytes[16:]

            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)

            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json) # Return the original dict
        except (ValueError, KeyError) as e:
            print(f"[!] AES decryption/unpadding error: {e}")
            return None # Indicate failure
        except json.JSONDecodeError as e:
            print(f"[!] JSON decoding error after decryption: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected AES decryption error: {e}")
            return None


    def send_message(self, msg_type_code, payload_dict):
        """Encrypt payload and send message with custom header"""
        if not self.connected or not self.client_socket or not self.aes_key:
            # Don't print error here for disconnect message itself
            if msg_type_code != MSG_DISCONNECT:
                 print(f"[!] Cannot send '{msg_type_code.strip()}': Not connected or no key.")
            return False
        try:
            # Encrypt the payload dictionary
            encrypted_payload = self._encrypt_aes(payload_dict)
            if not encrypted_payload:
                print(f"[!] Failed to encrypt payload for '{msg_type_code.strip()}'")
                return False

            # Prepare headers
            type_header = msg_type_code.ljust(HEADER_TYPE_LEN).encode('utf-8')
            size_header = str(len(encrypted_payload)).ljust(HEADER_SIZE_LEN).encode('utf-8')

            # Send headers + encrypted payload
            self.client_socket.sendall(type_header + size_header + encrypted_payload)
            # print(f"[*] Sent: {msg_type_code.strip()}, Size={len(encrypted_payload)}") # Debug
            return True

        except socket.error as e:
            print(f"[!] Socket error sending '{msg_type_code.strip()}': {e}")
            self.disconnect() # Disconnect on socket error
            return False
        except Exception as e:
            print(f"[!] Error sending message '{msg_type_code.strip()}': {e}")
            return False

    def _receive_messages(self):
        """Receive and process messages from the server using custom protocol"""
        buffer = b""
        expected_len = -1
        msg_type = None

        header_len = HEADER_TYPE_LEN + HEADER_SIZE_LEN

        while self.connected and self.client_socket and self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    print("[!] Connection closed by server (received empty data).")
                    self.disconnect()
                    break
                buffer += data

                while True: # Process buffer for multiple messages
                    if expected_len == -1: # Waiting for header
                        if len(buffer) >= header_len:
                            # Extract header
                            type_header = buffer[:HEADER_TYPE_LEN].decode('utf-8').strip()
                            size_header = buffer[HEADER_TYPE_LEN:header_len].decode('utf-8').strip()
                            buffer = buffer[header_len:]

                            try:
                                expected_len = int(size_header)
                                msg_type = type_header
                                # print(f"[*] Expecting Type: {msg_type}, Len: {expected_len}") # Debug
                            except ValueError:
                                print(f"[!] Invalid size header received: '{size_header}'")
                                self.disconnect() # Protocol error, disconnect
                                return # Exit thread

                        else:
                            break # Need more data for header

                    if expected_len != -1 and len(buffer) >= expected_len: # Have complete payload
                        # Extract encrypted payload
                        encrypted_payload = buffer[:expected_len]
                        buffer = buffer[expected_len:]


                        # Decrypt and process
                        message_payload = self._decrypt_aes(encrypted_payload)
                        if message_payload:
                            # Pass the string type code and the decrypted payload dict
                            self._handle_message(msg_type, message_payload)
                        else:
                            print(f"[!] Failed to decrypt/parse message of type '{msg_type}', skipping.")

                        # Reset for next message
                        expected_len = -1
                        msg_type = None
                    else:
                        break # Need more data for payload

            except socket.timeout:
                # Should not happen with timeout=None, but handle defensively
                print("[!] Socket timeout during receive.")
                time.sleep(0.1)
                continue
            except socket.error as e:
                if self.connected: # Avoid error message if disconnect was intended
                    print(f"[!] Socket error receiving message: {e}")
                self.disconnect()
                break # Exit loop
            except Exception as e:
                print(f"[!] Error receiving or processing message: {e}")
                import traceback
                traceback.print_exc() # Print detailed traceback for debugging
                self.disconnect()
                break # Exit loop

        print("[*] Receiver thread finished.")


    def _handle_message(self, msg_type, payload):
        """Handle different types of messages received from the server"""
        # print(f"[*] Received Type: {msg_type}, Payload: {payload}") # Debug

        if msg_type == MSG_SCREEN: # Screenshot
            img_data = payload.get('data')
            if img_data:
                try:
                    img_bytes = base64.b64decode(img_data)
                    # Process in GUI thread
                    if self.root:
                        self.root.after(0, self._display_screenshot, img_bytes)

                    # Calculate FPS
                    self.frames_received += 1
                    now = time.time()
                    elapsed = now - self.last_fps_update
                    if elapsed >= 1.0:
                        fps = self.frames_received / elapsed
                        if self.root and self.fps_var:
                             self.root.after(0, self.fps_var.set, f"{fps:.1f} FPS")
                        self.last_fps_update = now
                        self.frames_received = 0
                except (TypeError, ValueError, base64.binascii.Error) as e:
                    print(f"[!] Error decoding screenshot data: {e}")
                except Exception as e:
                     print(f"[!] Error handling screenshot: {e}")
            else:
                print("[!] Received screenshot message with no data.")

        elif msg_type == MSG_MSG: # Server message
            content = payload.get('content', 'No content')
            print(f"[Server]: {content}")

        elif msg_type == MSG_ERR: # Server error
             error_msg = payload.get('message', 'Unknown server error')
             print(f"[!] Server Error: {error_msg}")

        else:
            print(f"[?] Received unknown message type code: {msg_type}")


    def _display_screenshot(self, img_bytes):
        """Update the screenshot label with the new image (run in GUI thread)"""
        if not self.root or not self.screenshot_label or not self.screenshot_label.winfo_exists():
             return # Exit if GUI elements are gone

        try:
            img = Image.open(io.BytesIO(img_bytes))
            # Keep a reference to avoid garbage collection!
            photo_image = ImageTk.PhotoImage(img)
            self.screenshot_label.config(image=photo_image)
            self.screenshot_label.image = photo_image # Keep reference

            # Update scroll region after image is loaded
            self.screenshot_label.update_idletasks() # Ensure label size is updated
            self.screenshot_canvas.configure(scrollregion=self.screenshot_canvas.bbox("all"))

        except Exception as e:
            print(f"[!] Error displaying screenshot in Tkinter: {e}")

    def _win32_event_filter(self, msg, data):
        """Filter function for the Win32 keyboard hook to ignore injected events"""
        # Skip injected events (bit 0x10 in flags)
        if hasattr(data, 'flags') and data.flags & 0x10:
            # print(f"[*] Filtered injected event: {msg}, {data}") # Debug
            return False
        return True

    def _start_keyboard_listener(self):
        """Start the pynput keyboard listener"""
        if self.keyboard_listener:
            print("[!] Keyboard listener already running.")
            return

        def on_press(key):
            # Fast return if not active (don't even queue the event)
            if not self.connected or not self.screen_sharing_active:
                return
           
            try:
                if hasattr(key, 'char') and key.char:
                    key_id = key.char
                    key_type = 'char'
                else:
                    key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                    key_id = key_name
                    key_type = 'special'

                # Create unique key identifier
                unique_key_repr = f"{key_type}:{key_id}"
                
                # Only queue if not already pressed
                if unique_key_repr not in self.pressed_keys:
                    self.pressed_keys.add(unique_key_repr)
                    # Add to queue instead of direct send
                    self.key_event_queue.put(('down', key_id, key_type))
                    # print(f"[*] Key press queued: {unique_key_repr}") # Debug

            except Exception as e:
                print(f"[!] Error handling key press: {e}")

        def on_release(key):
                """Handle key release events"""
                # Check connection status at the beginning of the handler
                if not self.connected:
                    # Listener might still be running briefly after disconnect initiated
                    return False  # Stop listener if disconnected
                    
                # Only process release if screen sharing was active
                if not self.screen_sharing_active:
                    return
                    
                try:
                    if hasattr(key, 'char') and key.char:
                        key_id = key.char
                        key_type = 'char'
                    else:
                        key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                        key_id = key_name
                        key_type = 'special'
                        
                    unique_key_repr = f"{key_type}:{key_id}"
                    
                    # Remove from pressed set and queue release event
                    if unique_key_repr in self.pressed_keys:
                        self.pressed_keys.remove(unique_key_repr)
                        # Queue event instead of direct send to avoid blocking
                        self.key_event_queue.put(('up', key_id, key_type))
                        # print(f"[*] Key released: {unique_key_repr}") # Debug
                        
                except Exception as e:
                    print(f"[!] Error handling key release: {e}")

        # Start listener in a separate thread
        try:
            # Create listener with win32 event filter to avoid injected events
            self.keyboard_listener = keyboard.Listener(
                on_press=on_press,
                on_release=on_release,
                win32_event_filter=self._win32_event_filter)
            self.keyboard_listener.start()
            print("[*] Keyboard listener started.")
        except Exception as e:
            print(f"[!] Failed to start keyboard listener: {e}")
            # Optionally, disable keyboard control in GUI if listener fails
            if self.keyboard_status_var:
                self.keyboard_status_var.set("Listener Error")

if __name__ == "__main__":
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
    client.start_gui()