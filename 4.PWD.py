# Importing necessary libraries
import re  # Regular expression library for string matching and manipulation.
import webbrowser  # Library to open URLs in a web browser.
import threading  # Library to handle concurrent execution of threads.
import tldextract  # Library to extract domain, subdomain, and suffix from URLs.
from flask import Flask, render_template_string, request, redirect, url_for  # Flask framework for creating a web application.
import Levenshtein  # Library to calculate the Levenshtein distance between strings.

app = Flask(__name__)  # Creating a Flask application instance.

# Trusted domains list
trusted_domains = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'microsoft.com',
    'apple.com', 'adobe.com', 'paypal.com', 'dropbox.com', 'whatsapp.com'
]  # A list of trusted domains to compare against user input.

# HTML Template
template = """
<!DOCTYPE html> <!-- Declares the document type and version of HTML. -->
<html>
<head>
    <title>Phishing Website Detector</title> <!-- Title of the webpage displayed in the browser tab. -->
    <style>
        body {
            font-family: Arial, sans-serif; /* Sets the font family for the entire page. */
            background: #eef2f7; /* Sets a light blue-gray background color for the page. */
            display: flex; /* Uses Flexbox to center the content vertically and horizontally. */
            justify-content: center; /* Centers the content horizontally. */
            align-items: center; /* Centers the content vertically. */
            height: 100vh; /* Sets the height of the body to 100% of the viewport height. */
        }
        .container {
            background: white; /* Sets the background color of the container to white. */
            padding: 30px; /* Adds padding inside the container for spacing. */
            border-radius: 15px; /* Rounds the corners of the container. */
            box-shadow: 0 5px 15px rgba(0,0,0,0.2); /* Adds a subtle shadow effect to the container. */
            width: 500px; /* Sets a fixed width for the container. */
            text-align: center; /* Centers the text inside the container. */
        }
        input[type="text"] {
            width: 90%; /* Makes the input field take up 90% of the container's width. */
            padding: 10px; /* Adds padding inside the input field for better usability. */
            border-radius: 8px; /* Rounds the corners of the input field. */
            border: 1px solid #ccc; /* Adds a light gray border around the input field. */
            margin-bottom: 20px; /* Adds space below the input field. */
        }
        .buttons {
            display: flex; /* Uses Flexbox to align buttons horizontally. */
            justify-content: space-around; /* Distributes buttons evenly with space between them. */
        }
        input[type="submit"], button {
            background: #4CAF50; /* Sets the background color of the "Check URL" button to green. */
            color: white; /* Sets the text color of the button to white. */
            padding: 10px 25px; /* Adds padding inside the button for better clickability. */
            border: none; /* Removes the default border of the button. */
            border-radius: 8px; /* Rounds the corners of the button. */
            cursor: pointer; /* Changes the cursor to a pointer when hovering over the button. */
        }
        button {
            background: #f44336; /* Sets the background color of the "Clear" button to red. */
        }
        .result {
            margin-top: 20px; /* Adds space above the result section. */
            padding: 15px; /* Adds padding inside the result section for spacing. */
            border-radius: 10px; /* Rounds the corners of the result section. */
            font-size: 18px; /* Sets the font size of the result text. */
        }
        .legit {
            background-color: #d4edda; /* Sets the background color for legitimate results (green). */
            color: #155724; /* Sets the text color for legitimate results (dark green). */
        }
        .phishing {
            background-color: #f8d7da; /* Sets the background color for phishing results (red). */
            color: #721c24; /* Sets the text color for phishing results (dark red). */
        }
        .confidence, .accuracy, .rating {
            margin-top: 10px; /* Adds space above these sections for better readability. */
            font-size: 16px; /* Sets the font size for these sections. */
        }
        .stars {
            color: gold; /* Sets the color of the star rating to gold. */
            font-size: 24px; /* Sets the font size of the stars. */
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Phishing Website Detector</h2> <!-- Main heading of the webpage. -->
        <form method="post"> <!-- Form to submit user input. -->
            <input type="text" name="url" placeholder="Enter website URL" value="{{ url or '' }}" required><br>
            <!-- Input field for entering the URL. Placeholder provides guidance to the user. The "value" attribute dynamically fills the field if available. -->
            <div class="buttons">
                <input type="submit" value="Check URL"> <!-- Submit button to check the URL. -->
                <button type="submit" name="clear" value="clear">Clear</button> <!-- Clear button to reset the form. -->
            </div>
        </form>
        {% if result %}
            <div class="result {{ result_class }}"> <!-- Displays the result (legitimate or phishing). -->
                {{ result }} <!-- Dynamically inserts the result message (e.g., "Legitimate Website"). -->
            </div>
            <div class="confidence"><strong>Confidence:</strong> {{ confidence }}%</div> <!-- Displays the confidence score. -->
            <div class="accuracy"><strong>Model Accuracy:</strong> {{ accuracy }}%</div> <!-- Displays the model accuracy. -->
            <div class="rating"><strong>Rating:</strong> <span class="stars">{{ stars|safe }}</span></div> <!-- Displays the star rating. -->
        {% endif %} <!-- Ends the conditional block for displaying results. -->
    </div>
</body>
</html>
"""  # HTML template for rendering the phishing detector UI with dynamic content.

# Check domain spelling
def is_domain_misspelled(url):
    extracted = tldextract.extract(url)  # Extracts subdomain, domain, and suffix from the URL.
    domain = f"{extracted.domain}.{extracted.suffix}".lower()  # Combines domain and suffix into a lowercase string.
    return domain not in [t.lower() for t in trusted_domains]  # Checks if the domain is not in the trusted domains list.

# Dynamically calculate confidence
def calculate_confidence(url):
    extracted = tldextract.extract(url)  # Extracts subdomain, domain, and suffix from the URL.
    full_domain = f"{extracted.domain}.{extracted.suffix}".lower()  # Combines domain and suffix into a lowercase string.
    distances = [Levenshtein.distance(full_domain, trusted) for trusted in trusted_domains]  # Calculates Levenshtein distance between the input domain and each trusted domain.
    min_distance = min(distances)  # Finds the smallest distance (most similar trusted domain).
    subdomain_penalty = len(extracted.subdomain.split('.')) * 5 if extracted.subdomain else 0  # Adds penalty for long subdomains.
    total_penalty = min_distance * 10 + subdomain_penalty  # Calculates total penalty based on distance and subdomain length.
    confidence = max(20, 100 - total_penalty)  # Calculates confidence score, ensuring it doesn't drop below 20%.
    return confidence  # Returns the calculated confidence score.

# Dynamic star rating
def get_star_rating(confidence, is_phishing):
    if is_phishing:
        # For phishing websites: higher confidence = more stars (more dangerous)
        if confidence >= 80:  # If confidence is very high, return 5 stars.
            return '★★★★★'
        elif confidence >= 60:  # If confidence is moderately high, return 4 stars.
            return '★★★★☆'
        elif confidence >= 40:  # If confidence is moderate, return 3 stars.
            return '★★★☆☆'
        elif confidence >= 20:  # If confidence is low, return 2 stars.
            return '★★☆☆☆'
        else:  # If confidence is very low, return 1 star.
            return '★☆☆☆☆'
    else:
        # For legitimate websites: higher confidence = more stars (more trustworthy)
        if confidence >= 90:  # If confidence is very high, return 5 stars.
            return '★★★★★'
        elif confidence >= 70:  # If confidence is moderately high, return 4 stars.
            return '★★★★☆'
        elif confidence >= 50:  # If confidence is moderate, return 3 stars.
            return '★★★☆☆'
        elif confidence >= 30:  # If confidence is low, return 2 stars.
            return '★★☆☆☆'
        else:  # If confidence is very low, return 1 star.
            return '★☆☆☆☆'

# Dynamic accuracy based on sample test URLs
def compute_accuracy():
    test_data = [
        ('https://google.com', False),  # Test case for a legitimate website.
        ('https://facebook.com', False),  # Test case for a legitimate website.
        ('https://paypal.com', False),  # Test case for a legitimate website.
        ('https://faceboook.com', True),  # Test case for a phishing website (misspelled domain).
        ('https://secure-paypol.com', True),  # Test case for a phishing website (misspelled domain).
        ('https://dropbox-fileshare.com', True),  # Test case for a phishing website (untrusted domain).
        ('https://netflix.com', False),  # Test case for a legitimate website.
        ('https://amazonn.com', True)  # Test case for a phishing website (misspelled domain).
    ]  # A list of test URLs and their expected phishing status.
    correct = 0  # Counter for correct predictions.
    for url, expected_phishing in test_data:  # Iterates through each test case.
        prediction = is_domain_misspelled(url)  # Predicts whether the domain is phishing.
        if prediction == expected_phishing:  # Compares the prediction with the expected result.
            correct += 1  # Increments the counter if the prediction matches the expected result.
    return int((correct / len(test_data)) * 100)  # Calculates and returns the accuracy as a percentage.

@app.route('/', methods=['GET', 'POST'])  # Defines the root route for the Flask app, allowing GET and POST requests.
def index():
    if request.method == 'POST':  # Checks if the request method is POST.
        if 'clear' in request.form:  # Checks if the "Clear" button was clicked.
            return redirect(url_for('index'))  # Redirects to the homepage to clear the form.

        url = request.form['url']  # Retrieves the URL entered by the user.
        phishing = is_domain_misspelled(url)  # Checks if the domain is misspelled or untrusted.
        confidence = calculate_confidence(url)  # Calculates the confidence score for the URL.
        stars = get_star_rating(confidence, phishing)  # Gets the star rating based on the confidence score and phishing status.
        accuracy = compute_accuracy()  # Computes the accuracy of the model using test data.

        if phishing:
            result = "⚠️ Phishing Website."  # Displays a warning message for phishing websites.
            result_class = 'phishing'  # Applies the "phishing" CSS class for styling.
        else:
            result = "✅ Legitimate Website."  # Displays a success message for legitimate websites.
            result_class = 'legit'  # Applies the "legit" CSS class for styling.

        return render_template_string(
            template,
            url=url,  # Passes the entered URL to the template.
            result=result,  # Passes the result message to the template.
            result_class=result_class,  # Passes the CSS class for styling the result.
            confidence=confidence,  # Passes the confidence score to the template.
            accuracy=accuracy,  # Passes the model accuracy to the template.
            stars=stars  # Passes the star rating to the template.
        )  # Renders the HTML template with dynamic content.

    return render_template_string(template)  # Renders the HTML template for GET requests.

# Open in browser
def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')  # Opens the Flask app in the default web browser.

if __name__ == '__main__':
    threading.Timer(1.0, open_browser).start()  # Starts a timer to open the browser after 1 second.
    app.run(debug=False)  # Runs the Flask app in production mode (debugging disabled).
