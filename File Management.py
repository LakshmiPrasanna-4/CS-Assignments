# Import necessary libraries for GUI and file operations
import tkinter as tk  # Import the tkinter library to create the GUI (Graphical User Interface)
from tkinter import filedialog, messagebox  # Import filedialog for selecting files and messagebox for displaying error messages
import os  # Import the os module to work with the operating system, such as checking if files exist
import hashlib  # Import hashlib to generate hash values (SHA-256)
import subprocess  # Import subprocess to run system commands, such as opening files with default applications
import sys  # Import sys to interact with the system, particularly for platform-specific operations (e.g., Windows vs macOS)

# Function to browse and select a file from the system
def browse_path():
    """Open a file selection dialog and display the selected file's path."""
    path = filedialog.askopenfilename()  # Open a file dialog to allow the user to select a file
    if path:  # If the user selects a file (path is not empty)
        # Clear previous selections from the path and hash fields
        entry_path.delete(0, tk.END)  # Clear the file path entry widget
        entry_hash.delete(0, tk.END)  # Clear the file hash entry widget
        # Display the selected file path in the entry widget
        entry_path.insert(0, path)  # Insert the file path into the entry widget
        # Generate and display the hash for the selected file
        current_hash = generate_hash(path)  # Call the generate_hash function to calculate the file's hash
        if current_hash:  # If the hash is successfully generated
            entry_hash.insert(0, current_hash)  # Insert the generated hash into the hash entry widget

# Function to generate SHA-256 hash for the file at the given path
def generate_hash(file_path):
    """Generate SHA-256 hash of the selected file."""
    hash_sha256 = hashlib.sha256()  # Create a SHA-256 hash object
    try:
        with open(file_path, 'rb') as file:  # Open the file in binary read mode ('rb')
            while chunk := file.read(8192):  # Read the file in chunks of 8192 bytes to avoid loading large files into memory
                hash_sha256.update(chunk)  # Update the hash object with the current chunk
        return hash_sha256.hexdigest()  # Return the hash as a hexadecimal string
    except Exception as e:
        # If an error occurs (e.g., file not found, access denied), show an error message
        messagebox.showerror("Error", f"Failed to generate hash: {e}")  # Display an error message in the GUI
        return None  # Return None if hash generation fails (error occurred)

# Function to open the selected file in the default system application (e.g., text editor, browser)
def open_file(path):
    """Open the selected file in the default application."""
    try:
        # For Windows, use 'start' command to open the file with the default application
        if sys.platform == 'win32':  # Check if the system is Windows
            subprocess.Popen(['start', '', path], shell=True)  # Run the 'start' command to open the file
        else:  # For Linux or macOS, use the 'open' command
            subprocess.Popen(['open', path])  # Run the 'open' command to open the file
    except Exception as e:
        # If an error occurs while opening the file (e.g., file not found, access issues), show an error message
        messagebox.showerror("Error", f"Failed to open file: {e}")  # Display an error message in the GUI

# Function to verify the integrity of the file by comparing the hashes
def verify_integrity():
    """Verify the integrity of the selected file by checking its hash."""
    path = entry_path.get()  # Get the selected file path from the entry widget (from the user input)
    stored_hash = entry_hash.get()  # Get the stored hash value from the entry widget
    if not path or not stored_hash:  # If no file path or hash is provided, show an error message
        messagebox.showerror("Error", "Please select a file and generate its hash.")  # Display an error message
        return  # Exit the function without further processing
    if not os.path.exists(path):  # Check if the file exists at the given file path
        messagebox.showerror("Error", "The selected file does not exist.")  # Show an error if the file doesn't exist
        return  # Exit the function as the file doesn't exist
    current_hash = generate_hash(path)  # Generate the current hash of the selected file
    if current_hash == stored_hash:  # If the generated hash matches the stored hash
        messagebox.showinfo("Integrity Check", "File integrity verified.")  # Show an info message that the file is intact
        open_file(path)  # Open the file using the default application (e.g., text editor, browser)
    else:
        messagebox.showerror("Integrity Check Failed", "File has been modified.")  # Show an error message if the hashes don't match
        open_file(path)  # Open the file anyway so the user can inspect it

# Function to clear the file selection and hash display
def clear_selection():
    """Clear the current file selection and hash display."""
    entry_path.delete(0, tk.END)  # Clear the file path entry widget (reset the selection)
    entry_hash.delete(0, tk.END)  # Clear the hash entry widget (reset the displayed hash)

# Create the main application window
root = tk.Tk()  # Initialize the Tkinter window (root), which will serve as the main window for the GUI
root.title("File Integrity Checker")  # Set the title of the window to "File Integrity Checker"
root.geometry("600x200")  # Set the size of the window (width: 600, height: 200)

# Configure the grid layout of the window for better widget alignment
root.grid_rowconfigure(0, weight=1)  # Configure row 0 to have equal weight for vertical resizing
root.grid_rowconfigure(1, weight=1)  # Configure row 1 to have equal weight for vertical resizing
root.grid_rowconfigure(2, weight=1)  # Configure row 2 to have equal weight for vertical resizing
root.grid_rowconfigure(3, weight=1)  # Configure row 3 to have equal weight for vertical resizing
root.grid_rowconfigure(4, weight=1)  # Add an extra row for spacing (row 4) with equal weight
root.grid_columnconfigure(0, weight=1)  # Configure column 0 to have equal weight for horizontal resizing
root.grid_columnconfigure(1, weight=1)  # Configure column 1 to have equal weight for horizontal resizing
root.grid_columnconfigure(2, weight=1)  # Configure column 2 to have equal weight for horizontal resizing

# Path selection label and entry widget
tk.Label(root, text="Select File:").grid(row=0, column=0, padx=10, pady=5, sticky='e')  # Label for file selection
entry_path = tk.Entry(root, width=50)  # Entry widget to display the selected file path (user input)
entry_path.grid(row=0, column=1, padx=10, pady=5)  # Place the entry widget in the grid
tk.Button(root, text="Browse", command=browse_path).grid(row=1, column=1, pady=5)  # Button to open the file browser (browse for file)

# File hash display label and entry widget
tk.Label(root, text="File Hash (SHA-256):").grid(row=2, column=0, padx=10, pady=5, sticky='e')  # Label for file hash
entry_hash = tk.Entry(root, width=50)  # Entry widget to display the file's hash (generated by the program)
entry_hash.grid(row=2, column=1, padx=10, pady=5)  # Place the entry widget in the grid

# Button to verify file integrity
tk.Button(root, text="Verify Integrity", command=verify_integrity).grid(row=3, column=1, pady=5)  # Button to trigger the integrity verification process

# Spacer Row (Empty row for spacing between buttons)
tk.Label(root, text="").grid(row=4, column=1, pady=10)  # Empty label for vertical spacing (used to create spacing between buttons)

# Button to clear the file selection and hash display
tk.Button(root, text="Clear", command=clear_selection).grid(row=5, column=1, pady=5)  # Clear button to reset the file path and hash fields

# Run the Tkinter event loop to keep the window open
root.mainloop()  # Start the Tkinter event loop to display the window and handle user interactions
