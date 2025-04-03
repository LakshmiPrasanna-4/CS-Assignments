import re
import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Function to analyze password strength and return a score (out of 10)
def analyze_password_strength(password):
    score = 0  # Initialize score to 0

    # Check password length (>= 8 characters)
    if len(password) >= 8:  # If password is 8 or more characters
        score += 3  # Add 3 points for sufficient length
    else:
        score += 1  # Add 1 point if the password is too short
    
    # Check if password contains uppercase letters
    if re.search(r'[A-Z]', password):  # Search for any uppercase letters
        score += 2  # Add 2 points if it contains uppercase letters
    
    # Check if password contains lowercase letters
    if re.search(r'[a-z]', password):  # Search for any lowercase letters
        score += 2  # Add 2 points if it contains lowercase letters
    
    # Check if password contains digits
    if re.search(r'[0-9]', password):  # Search for any digits (0-9)
        score += 2  # Add 2 points if it contains digits
    
    # Check if password contains special characters
    if re.search(r'[@$!%*?&]', password):  # Search for special characters like @, $, !, %, etc.
        score += 1  # Add 1 point if it contains special symbols

    # Return the final password score (out of 10)
    return min(score, 10)  # Ensure score doesn't exceed 10

# Function to calculate data breach chances based on the password score
def calculate_data_breach_chances(password_score):
    # Inverse relationship: stronger password => lower breach chance
    if password_score == 10:  # Very strong password
        return 1  # Very low breach chance (1/10)
    elif 8 <= password_score <= 9:  # Strong password
        return 3  # Low breach chance (3/10)
    elif 5 <= password_score <= 7:  # Moderate password
        return 6  # Moderate breach chance (6/10)
    elif 3 <= password_score <= 4:  # Weak password
        return 8  # High breach chance (8/10)
    else:  # Very weak password (score 0-2)
        return 10  # Very high breach chance (10/10)

# Function to analyze and check password when manually entered
def analyze_and_check():
    password = entry_password.get()  # Get the entered password from the input field

    # Check if the password length is less than 8
    if len(password) < 8:  # If password is too short
        messagebox.showwarning("Invalid Password", "Password must be at least 8 characters long.")  # Show warning message
        return  # Exit the function early

    # Analyze the password strength
    strength_score = analyze_password_strength(password)  # Call the analyze_password_strength function
    result_label.config(text=f"Password Strength: {strength_score}/10")  # Display the strength score

    # Calculate the data breach chances (rating out of 10)
    breach_rating = calculate_data_breach_chances(strength_score)  # Calculate breach rating based on password strength
    breach_label.config(text=f"Data Breach Chances: {breach_rating}/10")  # Display breach chance message

    # Show messages based on password score
    if strength_score >= 7:  # If the score is 7 or higher
        messagebox.showinfo("Password Strength", "Password is strong!")  # Inform the user it's a strong password
    else:
        messagebox.showwarning("Password Strength", "Password is weak. Try to make it stronger.")  # Warn the user it’s weak

# Function to generate a secure password automatically based on user input
def generate_password():
    length = int(entry_length.get())  # Get desired password length from the input field
    secure_password = generate_secure_password(length)  # Call generate_secure_password function to generate a secure password
    generated_password_label.config(text=f"Generated Secure Password: {secure_password}")  # Display the generated password
    copy_button.config(state="normal", command=lambda: copy_password(secure_password))  # Enable the copy button and link it to the copy_password function

# Function to generate cryptographically secure passwords
def generate_secure_password(length=12):
    # Ensure the password has at least one uppercase letter, one lowercase letter, one digit, and one special symbol
    if length < 8:  # Check if the password length is less than 8 characters
        messagebox.showwarning("Invalid Length", "Password length must be at least 8 characters.")  # Show warning message
        return ""  # Return an empty string if the length is invalid

    # Define the character sets for different types
    uppercase = string.ascii_uppercase  # Uppercase English letters (A-Z)
    lowercase = string.ascii_lowercase  # Lowercase English letters (a-z)
    digits = string.digits  # Digits (0-9)
    special_characters = string.punctuation  # Special characters like !, @, #, etc.

    # Generate at least one character from each category
    password = [
        secrets.choice(uppercase),  # Randomly select an uppercase letter
        secrets.choice(lowercase),  # Randomly select a lowercase letter
        secrets.choice(digits),  # Randomly select a digit
        secrets.choice(special_characters)  # Randomly select a special character
    ]

    # Generate the remaining characters randomly from all available characters
    all_characters = uppercase + lowercase + digits + special_characters  # Combine all character sets
    password += [secrets.choice(all_characters) for _ in range(length - 4)]  # Add random characters to meet the desired length

    # Shuffle the password list to ensure randomness
    secrets.SystemRandom().shuffle(password)  # Use a secure random number generator to shuffle the password

    # Join the list into a string and return the password
    return ''.join(password)

# Function to copy password to clipboard
def copy_password(password):
    root.clipboard_clear()  # Clear the clipboard to prepare for copying
    root.clipboard_append(password)  # Append the generated password to the clipboard
    messagebox.showinfo("Copied", "Password copied to clipboard!")  # Show a confirmation message

# Function to clear the input fields and reset the UI
def clear_all():
    entry_password.delete(0, tk.END)  # Clear the password input field
    entry_length.delete(0, tk.END)  # Clear the length input field
    result_label.config(text="Password Strength: Not analyzed")  # Reset the result label
    breach_label.config(text="Data Breach Chances: Not analyzed")  # Reset breach chance label
    generated_password_label.config(text="Generated Secure Password: ")  # Reset the generated password label
    copy_button.config(state="disabled")  # Disable the copy button initially

# Function to handle password choice (manual or automatic)
def password_choice(choice):
    if choice == "manual":  # If the user chose manual entry
        password_frame.pack(fill="both", expand=True)  # Show the manual password entry frame
        length_frame.pack_forget()  # Hide the automatic generation frame
        analyze_button.pack(pady=10)  # Show the "Analyze Password" button
    else:  # If the user chose automatic generation
        length_frame.pack(fill="both", expand=True)  # Show the automatic password generation frame
        password_frame.pack_forget()  # Hide the manual entry frame
        generate_button.pack(pady=10)  # Show the "Generate Password" button

# Creating the main window
root = tk.Tk()  # Create the Tkinter root window
root.title("Password Strength Checker and Generator")  # Set the window title
root.geometry("500x500")  # Set the window size to 500x500 pixels

# Ask if manual or automatic
label_choice = tk.Label(root, text="Do you want to enter the password manually or automatically generate one?")  # Label asking the user for their choice
label_choice.pack(pady=20)  # Display the label with padding around it

button_manual = tk.Button(root, text="Enter Password Manually", command=lambda: password_choice("manual"))  # Button for manual password entry
button_manual.pack(pady=5)  # Display the button with padding

button_auto = tk.Button(root, text="Generate Password Automatically", command=lambda: password_choice("auto"))  # Button for automatic password generation
button_auto.pack(pady=5)  # Display the button with padding

# Manual Password Entry Frame
password_frame = tk.Frame(root)  # Create a frame for manual password entry

label_password = tk.Label(password_frame, text="Enter Password:")  # Label for the password input field
label_password.pack(pady=10)  # Display the label with padding

entry_password = tk.Entry(password_frame, width=30, show="*")  # Input field for the password (masked with asterisks)
entry_password.pack(pady=5)  # Display the entry field with padding

analyze_button = tk.Button(password_frame, text="Analyze Password", command=analyze_and_check)  # Button to analyze the entered password
analyze_button.pack(pady=10)  # Display the button with padding

result_label = tk.Label(password_frame, text="Password Strength: Not analyzed")  # Label to show the password strength result
result_label.pack(pady=5)  # Display the result label with padding

breach_label = tk.Label(password_frame, text="Data Breach Chances: Not analyzed")  # Label to show data breach chance
breach_label.pack(pady=5)  # Display the breach label with padding

# Automatic Password Generation Frame
length_frame = tk.Frame(root)  # Create a frame for automatic password generation

label_length = tk.Label(length_frame, text="Enter Desired Password Length:")  # Label for the password length input
label_length.pack(pady=10)  # Display the label with padding

entry_length = tk.Entry(length_frame, width=5)  # Input field for desired password length
entry_length.pack(pady=5)  # Display the entry field with padding

generate_button = tk.Button(length_frame, text="Generate Password", command=generate_password)  # Button to generate the password
generate_button.pack(pady=10)  # Display the button with padding

generated_password_label = tk.Label(length_frame, text="Generated Secure Password: ")  # Label to display the generated password
generated_password_label.pack(pady=5)  # Display the label with padding

copy_button = tk.Button(length_frame, text="Copy Password", state="disabled")  # Button to copy the password (disabled initially)
copy_button.pack(pady=5)  # Display the copy button with padding

# Clear Button
clear_button = tk.Button(root, text="Clear", command=clear_all)  # Button to clear the fields and reset the UI
clear_button.pack(pady=20)  # Display the button with padding

# Run the application
root.mainloop()  # Start the Tkinter event loop to run the application
