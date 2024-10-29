import socket
import ssl
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
import random

# Client configuration
HOST = 'localhost'
PORT = 12345
CERT_FILE = 'server.crt'

# Load vectorizer and model
with open("stopwords.txt", "r") as file:
    stopwords = file.read().splitlines()

vectorizer = TfidfVectorizer(stop_words=stopwords, lowercase=True, vocabulary=pickle.load(open("tfidfvectoizer.pkl", "rb")))
model = pickle.load(open("LinearSVCTuned.pkl", 'rb'))

# Global SSL client socket
ssl_client_socket = None

# Receive messages from the server
def receive_messages(chat_display):
    global ssl_client_socket
    while True:
        try:
            message = ssl_client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            display_message(chat_display, message, "incoming")
        except Exception as e:
            print(f"[ERROR] {e}")
            break

# Display messages in the chat with styles
def display_message(chat_display, message, msg_type):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_message = f"[{timestamp}] {message}\n"

    chat_display.config(state=tk.NORMAL)
    
    if msg_type == "incoming":
        chat_display.insert(tk.END, formatted_message, "incoming")
    elif msg_type == "outgoing":
        chat_display.insert(tk.END, formatted_message, "outgoing")
    elif msg_type == "warning":
        chat_display.insert(tk.END, formatted_message, "warning")
    
    chat_display.config(state=tk.DISABLED)
    chat_display.yview(tk.END)  # Auto-scroll to end

# Send message to server
def send_message(message_entry, chat_display):
    global ssl_client_socket
    message = message_entry.get().strip()
    if message:
        transformed_message = vectorizer.fit_transform([message])
        prediction = model.predict(transformed_message)[0]

        if prediction == 1:
            display_message(chat_display, "Warning: This message is classified as Toxic and will not be sent.", "warning")
        else:
            ssl_client_socket.send(message.encode('utf-8'))
            display_message(chat_display, f"You: {message}", "outgoing")
            message_entry.delete(0, tk.END)  # Clear the entry field
    else:
        messagebox.showwarning("Empty Message", "You cannot send an empty message!")

# Clear chat history
def clear_chat(chat_display):
    chat_display.config(state=tk.NORMAL)
    chat_display.delete(1.0, tk.END)
    chat_display.config(state=tk.DISABLED)

# Start the client connection
def start_client(chat_display, message_entry):
    client_conn_thread = threading.Thread(target=client_thread, args=(chat_display, message_entry))
    client_conn_thread.daemon = True
    client_conn_thread.start()

# Client connection handling thread
def client_thread(chat_display, message_entry):
    global ssl_client_socket
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERT_FILE)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client_socket = context.wrap_socket(client_socket, server_hostname=HOST)

    try:
        ssl_client_socket.connect((HOST, PORT))
        print(f"[INFO] Connected to {HOST}:{PORT}")
        receive_thread = threading.Thread(target=receive_messages, args=(chat_display,))
        receive_thread.start()
        message_entry.bind("<Return>", lambda event: send_message(message_entry, chat_display))
    except Exception as e:
        print(f"[ERROR] {e}")

# Set up the GUI
def create_gui():
    window = tk.Tk()
    window.title("Anonymous Chat Client")
    window.geometry("500x500")
    window.configure(bg="#34495e")

    # Chat display (read-only)
    chat_display = scrolledtext.ScrolledText(window, wrap=tk.WORD, state=tk.DISABLED, font=("Helvetica", 12), bg="#ecf0f1", fg="#2c3e50")
    chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Message entry field
    message_entry = tk.Entry(window, width=50, font=("Helvetica", 12), bg="#ecf0f1", fg="#2c3e50")
    message_entry.pack(padx=10, pady=5, fill=tk.X)

    # Frame for buttons
    button_frame = tk.Frame(window, bg="#34495e")
    button_frame.pack(pady=5)

    # Send button
    send_button = tk.Button(button_frame, text="Send", width=10, command=lambda: send_message(message_entry, chat_display), bg="#1abc9c", fg="white", font=("Helvetica", 10, "bold"))
    send_button.grid(row=0, column=0, padx=5)

    # Clear chat button
    clear_button = tk.Button(button_frame, text="Clear Chat", width=10, command=lambda: clear_chat(chat_display), bg="#e74c3c", fg="white", font=("Helvetica", 10, "bold"))
    clear_button.grid(row=0, column=1, padx=5)

    # Quit button
    quit_button = tk.Button(button_frame, text="Quit", width=10, command=window.quit, bg="#34495e", fg="white", font=("Helvetica", 10, "bold"))
    quit_button.grid(row=0, column=2, padx=5)

    # Start the client connection
    start_client(chat_display, message_entry)

    # Style tags for chat bubbles
    chat_display.tag_configure("incoming", background="#d1e7ff", justify="left", lmargin1=10, rmargin=10)
    chat_display.tag_configure("outgoing", background="#d1f2eb", justify="right", lmargin1=10, rmargin=10)
    chat_display.tag_configure("warning", background="#f5c6cb", justify="center", lmargin1=10, rmargin=10)

    # Start GUI event loop
    window.mainloop()

if __name__ == "__main__":
    create_gui()
