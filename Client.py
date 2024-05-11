import socket
import tkinter as tk
import threading

HOST = '127.0.0.1'  
PORT = 9999         

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_key = None

        self.setup_gui()

        self.connect_to_server()

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def setup_gui(self):
        self.root.title("Secured Chat Room")
        self.root.configure(bg='lavender')

        self.key_label = tk.Label(self.root, text="Enter Encryption/Decryption Key:", bg='lavender')
        self.key_label.pack(padx=10, pady=(10, 0))

        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.pack(padx=10, pady=5)

        self.key_button = tk.Button(self.root, text="Set Key", command=self.set_key, bg='lightblue')
        self.key_button.pack(padx=10, pady=5)

        self.modify_key_button = tk.Button(self.root, text="Modify Key", command=self.modify_key, bg='lightblue')
        self.modify_key_button.pack(padx=10, pady=5)
        self.modify_key_button.config(state=tk.DISABLED)

        self.encrypted_textbox_label = tk.Label(self.root, text="Encrypted Message:", bg='lavender')
        self.encrypted_textbox_label.pack(padx=10, pady=(10, 0))

        self.encrypted_textbox = tk.Text(self.root, height=5, width=50)
        self.encrypted_textbox.pack(padx=10, pady=5)
        self.encrypted_textbox.config(state=tk.DISABLED)

        self.decrypted_textbox_label = tk.Label(self.root, text="Decrypted Message:", bg='lavender')
        self.decrypted_textbox_label.pack(padx=10, pady=(10, 0))

        self.decrypted_textbox = tk.Text(self.root, height=5, width=50)
        self.decrypted_textbox.pack(padx=10, pady=5)
        self.decrypted_textbox.config(state=tk.DISABLED)

        self.input_text = tk.Entry(self.root, width=50)
        self.input_text.pack(padx=10, pady=10)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message, bg='lightblue')
        self.send_button.pack(padx=10, pady=10)

    def connect_to_server(self):
        try:
            self.client_socket.connect((HOST, PORT))
            self.key_button.config(state=tk.NORMAL)
        except Exception as e:
            print("Connection error:", e)
            self.root.destroy()

    def set_key(self):
        try:
            self.current_key = int(self.key_entry.get().strip())
            self.key_entry.config(state=tk.DISABLED)
            self.key_button.config(state=tk.DISABLED)
            self.modify_key_button.config(state=tk.NORMAL)
            self.key_label.config(text="Key set successfully!", fg="green")
        except ValueError:
            self.key_label.config(text="Invalid key. Please enter a valid integer.", fg="red")

    def modify_key(self):
        self.current_key = None
        self.key_entry.config(state=tk.NORMAL)
        self.key_button.config(state=tk.NORMAL)
        self.modify_key_button.config(state=tk.DISABLED)
        self.key_label.config(text="Enter Encryption/Decryption Key:", fg="black")

    def send_message(self):
        message = self.input_text.get().strip()
        if not message:
            return
        
        if self.current_key is None:
            tk.messagebox.showwarning("Key Not Set", "Please set encryption/decryption key.")
            return
        
        encrypted_message = self.encrypt(message)
        try:
            self.client_socket.send(encrypted_message.encode('utf-8'))
            self.update_textboxes('', encrypted_message)  # Display encrypted message
        except Exception as e:
            print("Send message error:", e)
            self.root.destroy()

        self.input_text.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_data = self.client_socket.recv(1024).decode('utf-8')
                if not encrypted_data:
                    break
                decrypted_message = self.decrypt(encrypted_data)
                self.update_textboxes(decrypted_message, encrypted_data)
            except Exception as e:
                print("Receive message error:", e)
                self.root.destroy()
                break

    def encrypt(self, message):
        return ''.join(chr(((ord(char) - ord('A' if char.isupper() else 'a') + self.current_key) % 26) + ord('A' if char.isupper() else 'a')) if char.isalpha() else char for char in message)

    def decrypt(self, message):
        return ''.join(chr(((ord(char) - ord('A' if char.isupper() else 'a') - self.current_key) % 26) + ord('A' if char.isupper() else 'a')) if char.isalpha() else char for char in message)

    def update_textboxes(self, decrypted_message, encrypted_message):
        self.decrypted_textbox.config(state=tk.NORMAL)
        self.decrypted_textbox.delete(1.0, tk.END)
        self.decrypted_textbox.insert(tk.END, decrypted_message)
        self.decrypted_textbox.config(state=tk.DISABLED)

        self.encrypted_textbox.config(state=tk.NORMAL)
        self.encrypted_textbox.delete(1.0, tk.END)
        self.encrypted_textbox.insert(tk.END, encrypted_message)
        self.encrypted_textbox.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()

if __name__ == "__main__":
    main()
