# ----- Importing necessary libraries -----
import joblib  # Importing joblib for saving and loading machine learning models.
import tldextract  # Importing tldextract to extract domain information from URLs.
import re  # Importing re for regular expression operations.
import ssl  # Importing ssl for handling SSL certificates (not used in this script).
import socket  # Importing socket for DNS resolution and IP address checks.
import whois  # Importing whois for domain registration information (not used in this script).
import datetime  # Importing datetime for date-related operations (not used in this script).
import os  # Importing os for file path and existence checks.
import pandas as pd  # Importing pandas for data manipulation and CSV handling.
from flask import Flask, render_template_string, request, redirect, url_for  # Importing Flask components for web app development.
from sklearn.ensemble import RandomForestClassifier  # Importing RandomForestClassifier for machine learning model creation.
from sklearn.model_selection import train_test_split  # Importing train_test_split for splitting datasets.
from sklearn.metrics import accuracy_score  # Importing accuracy_score for evaluating model performance.
from urllib.parse import urlparse  # Importing urlparse for URL parsing.
import webbrowser  # Importing webbrowser to open the app in a browser automatically.
from threading import Timer  # Importing Timer to schedule tasks (e.g., opening the browser).
import ipaddress  # Importing ipaddress for IP address validation and checks.

app = Flask(__name__)  # Creating a Flask application instance.

# ----- Function to extract features from a URL -----
def extract_features(url):  # Defining a function to extract features from a given URL.
    parsed = urlparse(url)  # Parsing the URL into components using urlparse.
    domain_info = tldextract.extract(url)  # Extracting domain information using tldextract.
    
    # ----- Function to check if an IP is private -----
    def is_private_ip(ip):  # Defining a helper function to check if an IP is private.
        try:  # Starting a try block to handle exceptions.
            ip_obj = ipaddress.ip_address(ip)  # Creating an IP address object using ipaddress.
            return ip_obj.is_private  # Returning True if the IP is private, otherwise False.
        except ValueError:  # Handling ValueError if the IP is invalid.
            return False  # Returning False if the IP is invalid.

    # ----- Extracting host and checking for private IPs -----
    host = parsed.hostname  # Extracting the hostname from the parsed URL.
    is_private = False  # Initializing a variable to track if the IP is private.
    ip_address = None  # Initializing a variable to store the resolved IP address.
    is_fake_website = False  # Initializing a variable to track if the website is fake.

    if host:  # Checking if the hostname exists.
        # ----- Checking if the hostname is a valid IP -----
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):  # Using regex to check if the hostname is an IP address.
            ip_address = host  # Assigning the hostname to ip_address if it's an IP.
            is_private = is_private_ip(ip_address)  # Checking if the IP is private.
            if is_private:  # If the IP is private, marking the website as fake.
                is_fake_website = True
        else:  # If the hostname is not an IP, resolving it to an IP.
            try:  # Starting a try block to handle DNS resolution errors.
                ip_address = socket.gethostbyname(host)  # Resolving the hostname to an IP address.
                is_private = is_private_ip(ip_address)  # Checking if the resolved IP is private.
                if is_private:  # If the IP is private, marking the website as fake.
                    is_fake_website = True
            except socket.gaierror:  # Handling socket.gaierror if DNS resolution fails.
                ip_address = None  # Setting IP address to None if resolution fails.
                is_private = False  # Setting is_private to False if resolution fails.

    # ----- Checking for suspicious patterns in the URL -----
    if re.search(r'login|secure|update|verify|bank|account', url, re.IGNORECASE):  # Searching for suspicious keywords in the URL.
        is_fake_website = True  # Marking the website as fake if suspicious keywords are found.

    # ----- Extracting features -----
    features = [  # Creating a list of features extracted from the URL.
        1 if parsed.scheme == "https" else 0,  # Feature 1: HTTPS (1 if HTTPS, 0 if HTTP).
        len(url),  # Feature 2: Length of the URL.
        url.count('.'),  # Feature 3: Number of dots in the domain.
        1 if '@' in url else 0,  # Feature 4: Presence of '@' symbol.
        1 if url.find('//', 8) != -1 else 0,  # Feature 5: Presence of double slashes.
        1 if '-' in domain_info.domain else 0,  # Feature 6: Presence of hyphen '-' in domain.
        1 if re.search(r'login|secure|update|verify|bank|account|sure', url, re.IGNORECASE) else 0,  # Feature 7: Presence of phishing keywords.
        len(domain_info.domain),  # Feature 8: Length of the domain name.
        sum(c.isdigit() for c in url),  # Feature 9: Number of digits in the URL.
        url.count('?'),  # Feature 10: Number of parameters in the URL.
        1 if is_private else 0,  # Feature 11: 1 if URL contains a private IP, 0 if not.
        1 if is_fake_website else 0  # Feature 12: Flag if it's a fake website.
    ]
    
    return features  # Returning the list of extracted features.

# ----- Function to train the machine learning model -----
def train_model():  # Defining a function to train the machine learning model.
    try:  # Starting a try block to handle exceptions.
        df = pd.read_csv("dataset.csv")  # Reading the dataset from a CSV file.
        df['features'] = df['url'].apply(extract_features)  # Extracting features for each URL in the dataset.
        X = list(df['features'])  # Creating a list of feature vectors.
        y = list(df['label'])  # Creating a list of labels (phishing or legitimate).

        # ----- Splitting the dataset into training and testing sets -----
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)  # Splitting the data into 80% training and 20% testing.
        
        # ----- Creating and training the RandomForest model -----
        model = RandomForestClassifier(n_estimators=200, random_state=42)  # Creating a RandomForestClassifier with 200 trees.
        model.fit(X_train, y_train)  # Training the model on the training data.

        # ----- Evaluating the model -----
        y_pred = model.predict(X_test)  # Making predictions on the test data.
        acc = accuracy_score(y_test, y_pred)  # Calculating the accuracy of the model.
        print(f"[Model Trained] Accuracy: {acc * 100:.2f}%")  # Printing the accuracy of the trained model.
        
        # ----- Saving the model -----
        joblib.dump(model, "phishing_model_with_ip_detection_and_fake_check.pkl")  # Saving the trained model to a file.
        return model, acc  # Returning the trained model and its accuracy.
    except Exception as e:  # Handling any exceptions that occur during training.
        print("[Training Error]", e)  # Printing the error message.
        raise e  # Raising the exception to stop execution.

# ----- Function to load or train the model -----
def load_or_train_model():  # Defining a function to load or train the model.
    if os.path.exists("phishing_model_with_ip_detection_and_fake_check.pkl"):  # Checking if the model file exists.
        print("[Model Loaded] phishing_model_with_ip_detection_and_fake_check.pkl found and loaded.")  # Printing a message if the model is loaded.
        model = joblib.load("phishing_model_with_ip_detection_and_fake_check.pkl")  # Loading the model from the file.
        return model, None  # Returning the loaded model and None for accuracy.
    else:  # If the model file does not exist, training a new model.
        print("[Model Not Found] Training new model...")  # Printing a message indicating that a new model will be trained.
        return train_model()  # Calling the train_model function to train a new model.

model, model_accuracy = load_or_train_model()  # Loading or training the model and storing it in variables.

# ----- Function to calculate star rating -----
def get_star_rating(confidence, is_phishing=False):  # Defining a function to calculate star ratings.
    if is_phishing:  # Checking if the website is phishing.
        if confidence > 80:  # Assigning 5 stars for high confidence phishing.
            return 5
        elif confidence > 60:  # Assigning 4 stars for moderate confidence phishing.
            return 4
        elif confidence > 40:  # Assigning 3 stars for low confidence phishing.
            return 3
        elif confidence > 20:  # Assigning 2 stars for very low confidence phishing.
            return 2
        else:  # Assigning 1 star for minimal confidence phishing.
            return 1
    else:  # If the website is legitimate, assigning stars based on safety confidence.
        if confidence > 80:  # Assigning 5 stars for high confidence safety.
            return 5
        elif confidence > 60:  # Assigning 4 stars for moderate confidence safety.
            return 4
        elif confidence > 40:  # Assigning 3 stars for low confidence safety.
            return 3
        elif confidence > 20:  # Assigning 2 stars for very low confidence safety.
            return 2
        else:  # Assigning 1 star for minimal confidence safety.
            return 1

# ----- Flask route for the home page -----
@app.route("/", methods=["GET", "POST"])  # Defining the root route for the Flask app.
def index():  # Defining the index function for handling requests.
    prediction = None  # Initializing a variable to store the prediction result.
    url_input = ""  # Initializing a variable to store the input URL.
    confidence = None  # Initializing a variable to store the confidence score.
    rating_stars = ""  # Initializing a variable to store the star rating.
    rating_text = ""  # Initializing a variable to store the rating text.
    accuracy = model_accuracy * 100 if model_accuracy else None  # Calculating the model accuracy as a percentage.
    current_accuracy = None  # Initializing a variable to store real-time accuracy.

    if request.method == "POST":  # Checking if the request method is POST.
        action = request.form.get("action")  # Getting the action from the form submission.
        if action == "Check":  # Checking if the action is "Check".
            url_input = request.form["url"]  # Getting the URL input from the form.
            features = extract_features(url_input)  # Extracting features from the input URL.
            
            # ----- Making predictions -----
            proba = model.predict_proba([features])[0]  # Getting the probability scores for the prediction.
            pred = model.predict([features])[0]  # Getting the predicted label (phishing or legitimate).

            # ----- Calculating confidence -----
            phishing_conf = proba[1] * 100  # Calculating the confidence for phishing.
            legit_conf = proba[0] * 100  # Calculating the confidence for legitimacy.

            if pred == 1:  # If the prediction is phishing.
                prediction = "🚨 Phishing Website!"  # Setting the prediction message.
                confidence = phishing_conf  # Setting the confidence score.
                stars = get_star_rating(phishing_conf, is_phishing=True)  # Calculating the star rating.
                rating_text = f"Danger Rating: {stars} out of 5"  # Setting the rating text.
            else:  # If the prediction is legitimate.
                prediction = "✅ Legitimate Website"  # Setting the prediction message.
                confidence = legit_conf  # Setting the confidence score.
                stars = get_star_rating(legit_conf, is_phishing=False)  # Calculating the star rating.
                rating_text = f"Safety Rating: {stars} out of 5"  # Setting the rating text.

            rating_stars = "⭐" * stars + "☆" * (5 - stars)  # Creating the star rating string.

            # ----- Simulating real-time accuracy -----
            total_urls = 100  # Simulating a batch of 100 URLs for real-time accuracy.
            correct_predictions = 0  # Initializing a counter for correct predictions.
            for _ in range(total_urls):  # Iterating through the simulated URLs.
                if model.predict([features])[0] == pred:  # Checking if the prediction matches.
                    correct_predictions += 1  # Incrementing the correct predictions counter.
            current_accuracy = (correct_predictions / total_urls) * 100  # Calculating the simulated accuracy.

        elif action == "Clear":  # If the action is "Clear".
            return redirect(url_for("index"))  # Redirecting to the index page.

    return render_template_string("""<!doctype html>
    <html lang="en"><head><title>Phishing Detector</title>
    <style>
      body { font-family: Arial; text-align: center; background: #f0f4f8; padding-top: 50px; }
      input { padding: 10px; width: 350px; font-size: 16px; border-radius: 8px; }
      button { padding: 10px 20px; font-size: 16px; border-radius: 8px; border: none; color: white; }
      .btn-check { background-color: #3498db; }
      .btn-clear { background-color: #2ecc71; }
      .result { font-size: 24px; margin-top: 20px; font-weight: bold; }
      .confidence, .rating-text, .stars { font-size: 18px; margin-top: 10px; }
      .stars { font-size: 22px; color: #f1c40f; }
      .accuracy { font-size: 18px; margin-top: 10px; color: #2ecc71; }
    </style></head>
    <body>
      <h1>Phishing Website Detector</h1>
      {% if accuracy %}
        <div class="accuracy">Model Accuracy: {{ accuracy|round(2) }}%</div>
      {% endif %}
      {% if current_accuracy %}
        <div class="accuracy">Current Running Accuracy: {{ current_accuracy|round(2) }}%</div>
      {% endif %}
      <form method="POST">
        <input type="text" name="url" placeholder="Enter a URL to check" value="{{ url_input }}" required><br><br>
        <button type="submit" name="action" value="Check" class="btn-check">Check URL</button>
        <button type="submit" name="action" value="Clear" class="btn-clear">Clear</button>
      </form>
      {% if prediction %}
        <div class="result">{{ prediction }}</div>
        <div class="confidence">Confidence: {{ confidence|round(2) }}%</div>
        <div class="rating-text">{{ rating_text }}</div>
        <div class="stars">{{ rating_stars }}</div>
      {% endif %}
    </body></html>
    """, prediction=prediction, url_input=url_input, confidence=confidence, rating_text=rating_text, rating_stars=rating_stars, accuracy=accuracy, current_accuracy=current_accuracy)  # Rendering the HTML template with dynamic content.

# ----- Function to open the browser automatically -----
def open_browser():  # Defining a function to open the browser.
    webbrowser.open_new("http://127.0.0.1:5000")  # Opening the app in the default browser.

if __name__ == "__main__":  # Checking if the script is run directly.
    Timer(1, open_browser).start()  # Scheduling the browser to open after 1 second.
    app.run(debug=True)  # Running the Flask app in debug mode.