import socket
import tkinter as tk
import threading
import random

HOST = '127.0.0.1'  # Server's IP address (localhost for testing)
PORT = 9999         # Port to connect to
SHARED_KEY = 11

def cipher(message, key):
    return ''.join(chr(((ord(char) - ord('A' if char.isupper() else 'a') + key) % 26) + ord('A' if char.isupper() else 'a')) if char.isalpha() else char for char in message)

def encrypt(message, key):
    return cipher(message, key)

def decrypt(message, key):
    return cipher(message, -key)

def receive_messages():
    while True:
        try:
            encrypted_data = client_socket.recv(1024).decode('utf-8')
            if not encrypted_data:
                break
            decrypted_message = decrypt(encrypted_data, SHARED_KEY)
            update_textbox(decrypted_message, encrypted_data)
        except ConnectionResetError:
            break

def send_message(message):
    encrypted_message = encrypt(message, SHARED_KEY)
    try:
        client_socket.send(encrypted_message.encode('utf-8'))
        update_textbox('', encrypted_message)  # Display encrypted message
    except ConnectionResetError:
        pass

def update_textbox(decrypted_message, encrypted_message):
    decrypted_textbox.config(state=tk.NORMAL)
    decrypted_textbox.delete(1.0, tk.END)
    decrypted_textbox.insert(tk.END, decrypted_message)
    decrypted_textbox.config(state=tk.DISABLED)

    encrypted_textbox.config(state=tk.NORMAL)
    encrypted_textbox.delete(1.0, tk.END)
    encrypted_textbox.insert(tk.END, encrypted_message)
    encrypted_textbox.config(state=tk.DISABLED)

def on_send_message():
    message = input_text.get().strip()
    send_message(message)
    input_text.delete(0, tk.END)

# GUI setup
root = tk.Tk()
root.title("Secured Chat Room")
root.configure(bg='lavender')  # Set background color to lavender

# Encrypted Message Display Area
encrypted_textbox_label = tk.Label(root, text="Encrypted Message:", bg='lavender')
encrypted_textbox_label.pack(padx=10, pady=(10, 0))

encrypted_textbox = tk.Text(root, height=5, width=50)
encrypted_textbox.pack(padx=10, pady=5)
encrypted_textbox.config(state=tk.DISABLED)

# Decrypted Message Display Area
decrypted_textbox_label = tk.Label(root, text="Decrypted Message:", bg='lavender')
decrypted_textbox_label.pack(padx=10, pady=(10, 0))

decrypted_textbox = tk.Text(root, height=5, width=50)
decrypted_textbox.pack(padx=10, pady=5)
decrypted_textbox.config(state=tk.DISABLED)

# Input Area
input_text = tk.Entry(root, width=50)
input_text.pack(padx=10, pady=10)

# Send Button
send_button = tk.Button(root, text="Send", command=on_send_message, bg='lightblue')
send_button.pack(padx=10, pady=10)

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Start receiving messages in a separate thread
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Start GUI main loop
root.mainloop()
