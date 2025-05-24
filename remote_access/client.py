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

MSG_KEY = "KEY "
MSG_SCREEN = "SCRN"
MSG_CONTROL = "CTRL"
MSG_MSG = "MESG"
MSG_ERR = "ERR "
MSG_DISCONNECT = "BYE "
HEADER_TYPE_LEN = 4

class Client:
    def __init__(self, server_host='127.0.0.1', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.server_public_key = None
        self.aes_key = None
        self.connected = False
        self.keyboard_listener = None
        self.pressed_keys = set()
        self.running = True

        self.screen_sharing_active = False

        self.key_event_queue = queue.Queue()
        self.key_processor_thread = None

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

        self.frames_received = 0
        self.last_fps_update = time.time()

    def _recv(self, sock):
        """Receives data prefixed with its size using the instance socket."""
        size_of_size_byte = b''
        while len(size_of_size_byte) < 1:
            try:
                packet = sock.recv(1 - len(size_of_size_byte))
                if not packet: return b''
                size_of_size_byte += packet
            except socket.error:
                return b''

        size_of_size = int.from_bytes(size_of_size_byte, 'big')

        size_bytes = b''
        while len(size_bytes) < size_of_size:
            try:
                packet = sock.recv(size_of_size - len(size_bytes))
                if not packet: return b''
                size_bytes += packet
            except socket.error:
                return b''

        data_len = int.from_bytes(size_bytes, 'big')

        data = b''
        while len(data) < data_len:
            try:
                packet = sock.recv(data_len - len(data))
                if not packet: return b''
                data += packet
            except socket.error:
                return b''

        return data

    def _send(self, sock, bdata):
        """Sends data prefixed with its size using the instance socket."""
        if isinstance(bdata, str):
            bdata = bdata.encode('utf-8')

        data_len = len(bdata)
        size_of_size = (data_len.bit_length() + 7) // 8
        if size_of_size == 0:
            size_of_size = 1

        size_bytes = data_len.to_bytes(size_of_size, 'big')
        size_of_size_byte = size_of_size.to_bytes(1, 'big')
        message = size_of_size_byte + size_bytes + bdata

        try:
            sock.sendall(message)
            return True
        except socket.error as e:
            print(f"Socket error during send: {e}")
            self.disconnect() # Disconnect on send error
            return False

    def start_gui(self):
        self.root = tk.Tk()
        self.root.title(f"Remote Control - {self.server_host}:{self.server_port}")
        self.root.geometry("1024x768")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)
        self.screenshot_frame = ttk.Frame(self.root)
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True)
        log_frame = ttk.Frame(self.root, padding=5)
        log_frame.pack(fill=tk.X)
        log_label = ttk.Label(log_frame, text="Console:")
        log_label.pack(side=tk.LEFT, padx=5)
        status_label = ttk.Label(control_frame, text="Status:")
        status_label.pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar(value="Disconnected")
        status_value = ttk.Label(control_frame, textvariable=self.status_var)
        status_value.pack(side=tk.LEFT, padx=5)
        self.connect_button = ttk.Button(control_frame, text="Connect", command=self.toggle_connection)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        screen_label = ttk.Label(control_frame, text="Screen Sharing:")
        screen_label.pack(side=tk.LEFT, padx=5)
        self.screen_button = ttk.Button(control_frame, text="Start", command=self.toggle_screen_sharing)
        self.screen_button.pack(side=tk.LEFT, padx=5)
        self.screen_button.config(state=tk.DISABLED)
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        keyboard_label = ttk.Label(control_frame, text="Keyboard:")
        keyboard_label.pack(side=tk.LEFT, padx=5)
        self.keyboard_status_var = tk.StringVar(value="Disabled")
        self.keyboard_status = ttk.Label(control_frame, textvariable=self.keyboard_status_var)
        self.keyboard_status.pack(side=tk.LEFT, padx=5)
        self.fps_var = tk.StringVar(value="0 FPS")
        fps_label = ttk.Label(control_frame, textvariable=self.fps_var)
        fps_label.pack(side=tk.RIGHT, padx=5)
        self.console_text = tk.Text(log_frame, height=6, wrap=tk.WORD)
        self.console_text.pack(fill=tk.X, expand=True, padx=5, pady=5)
        console_scrollbar = ttk.Scrollbar(self.console_text, command=self.console_text.yview)
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console_text.config(yscrollcommand=console_scrollbar.set)
        self._redirect_stdout()
        screenshot_container = ttk.Frame(self.screenshot_frame)
        screenshot_container.pack(fill=tk.BOTH, expand=True)
        h_scrollbar = ttk.Scrollbar(screenshot_container, orient=tk.HORIZONTAL)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        v_scrollbar = ttk.Scrollbar(screenshot_container)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.screenshot_canvas = tk.Canvas(screenshot_container, bg='black')
        self.screenshot_canvas.pack(fill=tk.BOTH, expand=True)
        h_scrollbar.config(command=self.screenshot_canvas.xview)
        v_scrollbar.config(command=self.screenshot_canvas.yview)
        self.screenshot_canvas.config(xscrollcommand=h_scrollbar.set, yscrollcommand=v_scrollbar.set)
        self.screenshot_inner_frame = ttk.Frame(self.screenshot_canvas)
        self.screenshot_canvas.create_window((0, 0), window=self.screenshot_inner_frame, anchor=tk.NW)
        self.screenshot_label = ttk.Label(self.screenshot_inner_frame)
        self.screenshot_label.pack()
        self.screenshot_inner_frame.bind("<Configure>",
            lambda e: self.screenshot_canvas.configure(
                scrollregion=self.screenshot_canvas.bbox("all")
            )
        )
        self.root.mainloop()

    def _redirect_stdout(self):
        class StdoutRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
                self.buffer = ""
            def write(self, string):
                self.buffer += string
                if '\n' in self.buffer:
                    lines = self.buffer.split('\n')
                    for line in lines[:-1]:
                        if self.text_widget.winfo_exists():
                            self.text_widget.after(0, self._add_line, line + '\n')
                    self.buffer = lines[-1]
            def _add_line(self, line):
                try:
                    if self.text_widget.winfo_exists():
                        self.text_widget.insert(tk.END, line)
                        self.text_widget.see(tk.END)
                except tk.TclError: pass
            def flush(self):
                if self.buffer and self.text_widget.winfo_exists():
                    self.text_widget.after(0, self._add_line, self.buffer)
                    self.buffer = ""
        sys.stdout = StdoutRedirector(self.console_text)
        sys.stderr = StdoutRedirector(self.console_text)

    def on_closing(self):
        print("[*] Closing application...")
        self.running = False
        self.disconnect()
        if self.root:
            self.root.destroy()

    def toggle_connection(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()
            self.running = True

    def toggle_screen_sharing(self):
        if not self.connected:
            print("[!] Not connected to server.")
            return
        if self.screen_sharing_active:
            self._clear_keyboard_state()
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
            self._clear_keyboard_state()

    def _clear_keyboard_state(self):
        if self.connected and self.screen_sharing_active:
            for key_data in list(self.pressed_keys): # Use list for safe iteration
                try:
                    key_type, key_id = key_data.split(':', 1)
                    self.key_event_queue.put(('up', key_id, key_type))
                except Exception as e:
                    print(f"[!] Error preparing key release {key_data}: {e}")
        self.pressed_keys.clear()
        print("[*] Local keyboard state cleared")

    def _process_key_events(self):
        while self.running:
            try:
                try:
                    event = self.key_event_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                state, key_id, key_type = event
                if self.connected and self.screen_sharing_active:
                    self.send_message(MSG_KEY, {
                        'key': key_id,
                        'key_kind': key_type,
                        'state': state
                    })
                    time.sleep(0.001)
                self.key_event_queue.task_done()
            except Exception as e:
                print(f"[!] Error processing key event: {e}")
        print("[*] Key processor thread terminated")

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            print(f"[*] Connecting to {self.server_host}:{self.server_port}...")
            self.client_socket.connect((self.server_host, self.server_port))
            self.client_socket.settimeout(None)
            print(f"[*] Connected to server at {self.server_host}:{self.server_port}")
            self._key_exchange()
            self.connected = True
            self.key_processor_thread = threading.Thread(target=self._process_key_events, daemon=True)
            self.key_processor_thread.start()
            print("[*] Key event processor thread started")
            if self.root:
                self.root.after(0, self._update_gui_connected)
            self._start_keyboard_listener()
            receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
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
        if not self.root or not self.status_var: return
        self.status_var.set(f"Connected to {self.server_host}:{self.server_port}")
        self.connect_button.config(text="Disconnect")
        self.screen_button.config(state=tk.NORMAL)

    def _update_gui_disconnected(self, reason="Disconnected"):
        if not self.root or not self.status_var: return
        self.status_var.set(reason)
        self.connect_button.config(text="Connect")
        self.screen_button.config(state=tk.DISABLED)
        self.screen_button.config(text="Start")
        self.keyboard_status_var.set("Disabled")
        self.fps_var.set("0 FPS")
        self.screenshot_label.config(image=None)
        self.current_screenshot = None

    def disconnect(self):
        if not self.connected: return
        was_connected = self.connected
        self.connected = False
        self.screen_sharing_active = False
        if self.client_socket:
             try:
                 if self.aes_key:
                     self.send_message(MSG_DISCONNECT, {})
             except Exception as e:
                 print(f"[!] Error sending disconnect message: {e}")
        if self.keyboard_listener:
            print("[*] Stopping keyboard listener...")
            self.keyboard_listener.stop()
            self.keyboard_listener = None
        self._clear_keyboard_state()
        if self.client_socket:
            print("[*] Closing socket...")
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except Exception as e:
                print(f"[!] Error closing socket: {e}")
            self.client_socket = None
        self.aes_key = None
        self.server_public_key = None
        if was_connected: print("[*] Disconnected from server")
        if self.root:
            self.root.after(0, self._update_gui_disconnected)

    def _key_exchange(self):
        try:
            print("[*] Receiving server public key...")
            server_public_key_bytes = self._recv(self.client_socket)
            if not server_public_key_bytes:
                raise ConnectionError("Server disconnected during key exchange (public key)")
            self.server_public_key = RSA.import_key(server_public_key_bytes)
            print("[*] Server public key received.")
            self.aes_key = get_random_bytes(32)
            print("[*] Encrypting AES key...")
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)
            print("[*] Sending encrypted AES key...")
            self._send(self.client_socket, encrypted_aes_key)
            print("[*] Secure connection established.")
        except Exception as e:
            print(f"[!] Key exchange failed: {e}")
            self.aes_key = None
            raise

    def _encrypt_aes(self, message_data):
        if not self.aes_key:
            print("[!] AES key not available for encryption.")
            return None
        try:
            message_json = json.dumps(message_data)
            message_bytes = message_json.encode('utf-8')
            iv = get_random_bytes(16)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            return iv + ct_bytes
        except Exception as e:
            print(f"[!] AES encryption error: {e}")
            return None

    def _decrypt_aes(self, encrypted_payload_bytes):
        if not self.aes_key:
            print("[!] AES key not available for decryption.")
            return None
        try:
            if len(encrypted_payload_bytes) < 16:
                 print("[!] Decryption error: Payload too short.")
                 return None
            iv = encrypted_payload_bytes[:16]
            ciphertext = encrypted_payload_bytes[16:]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json)
        except (ValueError, KeyError) as e:
            print(f"[!] AES decryption/unpadding error: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[!] JSON decoding error after decryption: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected AES decryption error: {e}")
            return None

    def send_message(self, msg_type_code, payload_dict):
        if not self.connected or not self.client_socket or not self.aes_key:
            if msg_type_code != MSG_DISCONNECT:
                 print(f"[!] Cannot send '{msg_type_code.strip()}': Not connected or no key.")
            return False
        try:
            encrypted_payload = self._encrypt_aes(payload_dict)
            if not encrypted_payload:
                print(f"[!] Failed to encrypt payload for '{msg_type_code.strip()}'")
                return False

            type_header = msg_type_code.ljust(HEADER_TYPE_LEN).encode('utf-8')
            full_message = type_header + encrypted_payload

            return self._send(self.client_socket, full_message)

        except Exception as e:
            print(f"[!] Error sending message '{msg_type_code.strip()}': {e}")
            return False

    def _receive_messages(self):
        while self.connected and self.client_socket and self.running:
            try:
                data = self._recv(self.client_socket)
                if not data:
                    print("[!] Connection closed by server or recv error.")
                    self.disconnect()
                    break

                if len(data) < HEADER_TYPE_LEN:
                    print(f"[!] Received message too short: {len(data)} bytes.")
                    continue

                msg_type = data[:HEADER_TYPE_LEN].decode('utf-8')
                encrypted_payload = data[HEADER_TYPE_LEN:]

                message_payload = self._decrypt_aes(encrypted_payload)
                if message_payload:
                    self._handle_message(msg_type, message_payload)
                else:
                    print(f"[!] Failed to decrypt/parse message of type '{msg_type}', skipping.")

            except Exception as e:
                if self.connected:
                    print(f"[!] Error receiving or processing message: {e}")
                    import traceback
                    traceback.print_exc()
                self.disconnect()
                break
        print("[*] Receiver thread finished.")


    def _handle_message(self, msg_type, payload):
        if msg_type == MSG_SCREEN:
            img_data = payload.get('data')
            if img_data:
                try:
                    img_bytes = base64.b64decode(img_data)
                    if self.root:
                        self.root.after(0, self._display_screenshot, img_bytes)
                    self.frames_received += 1
                    now = time.time()
                    elapsed = now - self.last_fps_update
                    if elapsed >= 1.0:
                        fps = self.frames_received / elapsed
                        if self.root and self.fps_var:
                             self.root.after(0, self.fps_var.set, f"{fps:.1f} FPS")
                        self.last_fps_update = now
                        self.frames_received = 0
                except Exception as e:
                     print(f"[!] Error handling screenshot: {e}")
            else:
                print("[!] Received screenshot message with no data.")
        elif msg_type == MSG_MSG:
            content = payload.get('content', 'No content')
            print(f"[Server]: {content}")
        elif msg_type == MSG_ERR:
             error_msg = payload.get('message', 'Unknown server error')
             print(f"[!] Server Error: {error_msg}")
        else:
            print(f"[?] Received unknown message type code: {msg_type}")

    def _display_screenshot(self, img_bytes):
        if not self.root or not self.screenshot_label or not self.screenshot_label.winfo_exists():
             return
        try:
            img = Image.open(io.BytesIO(img_bytes))
            photo_image = ImageTk.PhotoImage(img)
            self.screenshot_label.config(image=photo_image)
            self.screenshot_label.image = photo_image
            self.screenshot_label.update_idletasks()
            self.screenshot_canvas.configure(scrollregion=self.screenshot_canvas.bbox("all"))
        except Exception as e:
            print(f"[!] Error displaying screenshot in Tkinter: {e}")

    def _win32_event_filter(self, msg, data):
        if hasattr(data, 'flags') and data.flags & 0x10:
            return False
        return True

    def _start_keyboard_listener(self):
        if self.keyboard_listener:
            print("[!] Keyboard listener already running.")
            return
        def on_press(key):
            if not self.connected or not self.screen_sharing_active: return
            try:
                if hasattr(key, 'char') and key.char:
                    key_id = key.char
                    key_type = 'char'
                else:
                    key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                    key_id = key_name
                    key_type = 'special'
                unique_key_repr = f"{key_type}:{key_id}"
                if unique_key_repr not in self.pressed_keys:
                    self.pressed_keys.add(unique_key_repr)
                    self.key_event_queue.put(('down', key_id, key_type))
            except Exception as e:
                print(f"[!] Error handling key press: {e}")
        def on_release(key):
                if not self.connected: return False
                if not self.screen_sharing_active: return
                try:
                    if hasattr(key, 'char') and key.char:
                        key_id = key.char
                        key_type = 'char'
                    else:
                        key_name = getattr(key, 'name', str(key).replace('Key.', ''))
                        key_id = key_name
                        key_type = 'special'
                    unique_key_repr = f"{key_type}:{key_id}"
                    if unique_key_repr in self.pressed_keys:
                        self.pressed_keys.remove(unique_key_repr)
                        self.key_event_queue.put(('up', key_id, key_type))
                except Exception as e:
                    print(f"[!] Error handling key release: {e}")
        try:
            self.keyboard_listener = keyboard.Listener(
                on_press=on_press,
                on_release=on_release,
                win32_event_filter=self._win32_event_filter)
            self.keyboard_listener.start()
            print("[*] Keyboard listener started.")
        except Exception as e:
            print(f"[!] Failed to start keyboard listener: {e}")
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