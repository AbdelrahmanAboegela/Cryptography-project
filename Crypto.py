import tkinter as tk

def encrypt(message, key):
    encrypted_message = ""
    m = 26
    for char in message:
        if char.isalpha():
            if char.isupper():
                p = ord(char) - ord('A')
                encrypted_char = chr((p + key) % m + ord('A'))
            else:
                p = ord(char) - ord('a')
                encrypted_char = chr((p + key) % m + ord('a'))
            encrypted_message += encrypted_char
        else:
            encrypted_message += char
    return encrypted_message

def decrypt(message, key):
    decrypted_message = ""
    m = 26
    for char in message:
        if char.isalpha():
            if char.isupper():
                p = ord(char) - ord('A')
                decrypted_char = chr((p - key) % m + ord('A'))
            else:
                p = ord(char) - ord('a')
                decrypted_char = chr((p - key) % m + ord('a'))
            decrypted_message += decrypted_char
        else:
            decrypted_message += char
    return decrypted_message

def user1_encrypt_message():
    message = user1_input_text.get("1.0", tk.END).strip()
    encrypted_message = encrypt(message, shared_key)
    user2_input_text.delete("1.0", tk.END)
    user2_input_text.insert(tk.END, encrypted_message)
    user1_input_text.delete("1.0", tk.END)

def user1_decrypt_message():
    message = user1_input_text.get("1.0", tk.END).strip()
    decrypted_message = decrypt(message, shared_key)
    user1_output_text.delete("1.0", tk.END)
    user1_output_text.insert(tk.END, decrypted_message)
    user1_input_text.delete("1.0", tk.END)

def user2_decrypt_message():
    message = user2_input_text.get("1.0", tk.END).strip()
    decrypted_message = decrypt(message, shared_key)
    user2_output_text.delete("1.0", tk.END)
    user2_output_text.insert(tk.END, decrypted_message)
    user2_input_text.delete("1.0", tk.END)

def user2_encrypt_message():
    message = user2_input_text.get("1.0", tk.END).strip()
    encrypted_message = encrypt(message, shared_key)
    user1_input_text.delete("1.0", tk.END)
    user1_input_text.insert(tk.END, encrypted_message)
    user2_input_text.delete("1.0", tk.END)

# GUI setup
root = tk.Tk()
root.title("Encryption and Decryption")

# Customizing background color
root.configure(bg='lavender')

user1_frame = tk.Frame(root, bg='lavender')
user1_frame.pack(side=tk.LEFT, padx=10, pady=10)

user2_frame = tk.Frame(root, bg='lavender')
user2_frame.pack(side=tk.RIGHT, padx=10, pady=10)

# User 1 interface
user1_input_label = tk.Label(user1_frame, text="User 1 - Enter your message:", bg='lavender', fg='navy')
user1_input_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

user1_input_text = tk.Text(user1_frame, height=10, width=40)
user1_input_text.grid(row=1, column=0, padx=5, pady=5)

user1_encrypt_button = tk.Button(user1_frame, text="User 1 Encrypt", command=user1_encrypt_message, bg='lightblue')
user1_encrypt_button.grid(row=2, column=0, padx=5, pady=5, sticky='w')

user1_decrypt_button = tk.Button(user1_frame, text="User 1 Decrypt", command=user1_decrypt_message, bg='lightblue')
user1_decrypt_button.grid(row=3, column=0, padx=5, pady=5, sticky='w')

user1_output_label = tk.Label(user1_frame, text="User 1 - Decrypted:", bg='lavender', fg='navy')
user1_output_label.grid(row=4, column=0, padx=5, pady=5, sticky='w')

user1_output_text = tk.Text(user1_frame, height=10, width=40)
user1_output_text.grid(row=5, column=0, padx=5, pady=5)

# User 2 interface
user2_input_label = tk.Label(user2_frame, text="User 2 - Enter your message:", bg='lavender', fg='navy')
user2_input_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

user2_input_text = tk.Text(user2_frame, height=10, width=40)
user2_input_text.grid(row=1, column=0, padx=5, pady=5)

user2_decrypt_button = tk.Button(user2_frame, text="User 2 Decrypt", command=user2_decrypt_message, bg='lightblue')
user2_decrypt_button.grid(row=2, column=0, padx=5, pady=5, sticky='w')

user2_encrypt_button = tk.Button(user2_frame, text="User 2 Encrypt", command=user2_encrypt_message, bg='lightblue')
user2_encrypt_button.grid(row=3, column=0, padx=5, pady=5, sticky='w')

user2_output_label = tk.Label(user2_frame, text="User 2 - Decrypted:", bg='lavender', fg='navy')
user2_output_label.grid(row=4, column=0, padx=5, pady=5, sticky='w')

user2_output_text = tk.Text(user2_frame, height=10, width=40)
user2_output_text.grid(row=5, column=0, padx=5, pady=5)

# Key setup
shared_key = 11  # Shared key between users

root.mainloop()
