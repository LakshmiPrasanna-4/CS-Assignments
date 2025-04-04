# Import necessary libraries
from scapy.all import IP, TCP  # Import Scapy's IP and TCP layers for packet crafting and analysis.
import pandas as pd  # Import Pandas for data manipulation (e.g., loading CSV files).
import joblib  # Import Joblib for saving and loading machine learning models.
import threading  # Import threading to run the packet simulator in the background.
import time  # Import time for delays and timestamps.
import os  # Import OS module for file path checks.
import random  # Import random to generate random values for simulated packets.
import webbrowser  # Import webbrowser to open the dashboard automatically in the default browser.

from flask import Flask  # Import Flask for creating a web server.
import dash  # Import Dash for building the dashboard.
from dash import dcc, html  # Import Dash components for layout and interactivity (dcc for graphs, html for HTML elements).
from dash.dependencies import Input, Output, State  # Import Dash dependencies for callbacks (Input, Output, State).
from sklearn.ensemble import RandomForestClassifier  # Import Random Forest classifier from scikit-learn.
from sklearn.model_selection import train_test_split  # Import train_test_split for splitting datasets into training and testing sets.


# ========== Model Training Section ========== #
def train_model(path):  # Define a function to train the model. Takes `path` as input (the dataset file path).
    df = pd.read_csv(path)  # Load the dataset from the provided CSV file path using Pandas' `read_csv`.
    X = df.drop("label", axis=1) if "label" in df.columns else df.iloc[:, :-1]  # Drop the 'label' column to extract features; if 'label' doesn't exist, drop the last column.
    y = df["label"] if "label" in df.columns else (df.iloc[:, -1] != "normal.").astype(int)  # Extract labels; if 'label' exists, use it; otherwise, assume the last column contains binary labels ("normal." or not).
    model = RandomForestClassifier(n_estimators=100)  # Initialize a Random Forest classifier with 100 decision trees (`n_estimators=100`).
    model.fit(X, y)  # Train the Random Forest model on the extracted features (`X`) and labels (`y`).
    joblib.dump(model, "nids_model.pkl")  # Save the trained model to a file named 'nids_model.pkl' using Joblib's `dump`.


if not os.path.exists("nids_model.pkl"):  # Check if the pre-trained model file ('nids_model.pkl') exists in the current directory.
    dataset = input("📥 Enter CSV dataset path: ")  # Prompt the user to enter the path to the dataset file.
    train_model(dataset)  # Call the `train_model` function with the provided dataset path to train the model.

model = joblib.load("nids_model.pkl")  # Load the pre-trained model from the file 'nids_model.pkl' using Joblib's `load`.


# ========== Detection Logic ========== #
good_count = 0  # Initialize a counter to keep track of the number of good (non-malicious) packets detected.
bad_count = 0  # Initialize a counter to keep track of the number of bad (malicious) packets detected.
packet_logs = []  # Initialize an empty list to store logs of detected packets (including timestamps and summaries).
running = False  # Initialize a boolean flag to control whether the packet simulation is running or stopped.

packet_times = []  # Initialize an empty list to store timestamps of detected packets.
good_history = []  # Initialize an empty list to store the count of good packets over time.
bad_history = []  # Initialize an empty list to store the count of bad packets over time.


def extract_features(packet):  # Define a function to extract features from a given packet.
    return pd.DataFrame([{  # Create a Pandas DataFrame containing the extracted features as a dictionary.
        "packet_length": len(packet),  # Feature: Length of the packet (number of bytes).
        "protocol": 1 if TCP in packet else 0,  # Feature: Whether the packet uses TCP (1) or not (0).
        "src_port": packet[TCP].sport if TCP in packet else 0,  # Feature: Source port of the TCP packet; if no TCP layer, set to 0.
        "dst_port": packet[TCP].dport if TCP in packet else 0,  # Feature: Destination port of the TCP packet; if no TCP layer, set to 0.
        "flag_syn": int(packet[TCP].flags & 0x02 != 0) if TCP in packet else 0,  # Feature: Presence of the SYN flag (1 if present, 0 otherwise).
        "flag_ack": int(packet[TCP].flags & 0x10 != 0) if TCP in packet else 0  # Feature: Presence of the ACK flag (1 if present, 0 otherwise).
    }])  # End of DataFrame creation.


def generate_packet():  # Define a function to generate a random network packet for simulation.
    ip = IP(src=f"192.168.1.{random.randint(1,254)}", dst="192.168.1.1")  # Generate a random source IP address in the range 192.168.1.1 to 192.168.1.254 and a fixed destination IP (192.168.1.1).
    tcp = TCP(sport=random.randint(1024,65535), dport=random.choice([80,443]), flags="S")  # Generate a random TCP packet with a source port between 1024 and 65535, destination port either 80 (HTTP) or 443 (HTTPS), and SYN flag set.
    return ip/tcp  # Combine the IP and TCP layers into a single packet using Scapy's `/` operator.


def packet_simulator():  # Define a function to simulate network packets in a loop.
    global good_count, bad_count, packet_logs, packet_times, good_history, bad_history  # Use the `global` keyword to modify global variables inside this function.
    while True:  # Start an infinite loop to continuously simulate packets.
        if running:  # Check if the `running` flag is True (i.e., the simulation is active).
            pkt = generate_packet()  # Generate a random packet using the `generate_packet` function.
            features = extract_features(pkt)  # Extract features from the generated packet using the `extract_features` function.
            try:
                pred = model.predict(features)[0]  # Use the pre-trained model to predict whether the packet is good (0) or bad (1). `[0]` accesses the first prediction.
                if pred == 0:  # If the prediction is 0 (good packet):
                    packet_type = "Good"  # Label the packet as "Good".
                    good_count += 1  # Increment the `good_count` counter by 1.
                else:  # If the prediction is 1 (bad packet):
                    packet_type = "🚫 Blocked Bad Packet"  # Label the packet as "Blocked Bad Packet".
                    bad_count += 1  # Increment the `bad_count` counter by 1.
                timestamp = time.strftime("%H:%M:%S")  # Get the current timestamp in the format "HH:MM:SS" using `strftime`.
                summary = pkt.summary()  # Generate a summary of the packet using Scapy's `summary` method.
                packet_logs.append({"time": timestamp, "summary": summary, "type": packet_type})  # Append the packet details (timestamp, summary, and type) to the `packet_logs` list.
                packet_times.append(timestamp)  # Append the timestamp to the `packet_times` list.
                good_history.append(good_count)  # Append the current value of `good_count` to the `good_history` list.
                bad_history.append(bad_count)  # Append the current value of `bad_count` to the `bad_history` list.
            except:
                pass  # Ignore any errors that occur during prediction or logging (e.g., malformed packets).
        time.sleep(0.5)  # Pause the loop for 0.5 seconds before generating the next packet.


# ========== Web App Layout ========== #
server = Flask(__name__)  # Create a Flask server instance. `__name__` specifies the name of the current module.
app = dash.Dash(__name__, server=server, routes_pathname_prefix="/dashboard/")  # Create a Dash app attached to the Flask server. The `routes_pathname_prefix` defines the URL prefix for the dashboard ("/dashboard/").

app.layout = html.Div([  # Define the layout of the dashboard using Dash's `html.Div` component.
    html.H1("Intrusion Detection System", style={"textAlign": "center"}),  # Add a title to the dashboard ("Intrusion Detection System"). `style` centers the text.

    html.Div([
        html.Button("▶️ Start Detecting", id="start-btn", n_clicks=0, style={"marginRight": "10px"}),  # Add a button labeled "Start Detecting". `id` identifies the button, `n_clicks` tracks the number of clicks, and `style` adds a margin to the right.
        html.Button("⛔ Stop Detecting", id="stop-btn", n_clicks=0)  # Add a button labeled "Stop Detecting". `id` identifies the button, and `n_clicks` tracks the number of clicks.
    ], style={"textAlign": "center", "margin": "20px"}),  # Center the buttons and add a margin around them.

    html.Div([
        html.Div([
            html.H4("✅ Good Packets"),  # Add a subtitle for good packets ("Good Packets").
            html.Div(id="good-count", style={"fontSize": "24px", "color": "green"})  # Display the count of good packets. `id` identifies the element, and `style` sets the font size and color.
        ], style={"width": "48%", "display": "inline-block", "textAlign": "center"}),  # Set the width to 48%, display inline-block, and center the text.

        html.Div([
            html.H4("❗ Bad Packets"),  # Add a subtitle for bad packets ("Bad Packets").
            html.Div(id="bad-count", style={"fontSize": "24px", "color": "red"})  # Display the count of bad packets. `id` identifies the element, and `style` sets the font size and color.
        ], style={"width": "48%", "display": "inline-block", "textAlign": "center"})  # Set the width to 48%, display inline-block, and center the text.
    ]),

    dcc.Graph(id="live-graph"),  # Add a graph component to display the live traffic detection data. `id` identifies the graph.

    html.Div(id="packet-output", style={  # Add a div to display the latest packet logs. `id` identifies the element, and `style` defines its appearance.
        "padding": "10px",  # Add padding of 10 pixels.
        "marginTop": "20px",  # Add a margin of 20 pixels at the top.
        "border": "1px solid #ccc",  # Add a light gray border.
        "height": "200px",  # Set the height to 200 pixels.
        "overflowY": "scroll",  # Enable vertical scrolling if content exceeds the height.
        "backgroundColor": "#f9f9f9",  # Set the background color to light gray.
        "textAlign": "left"  # Align the text to the left.
    }),

    dcc.Interval(id="interval", interval=1000, n_intervals=0)  # Add an interval component to refresh the dashboard every second. `interval=1000` specifies 1000 milliseconds (1 second), and `n_intervals` tracks the number of intervals elapsed.
])


# ========== Callbacks ========== #
@app.callback(
    Output("good-count", "children"),  # Update the content of the "good-count" div.
    Output("bad-count", "children"),  # Update the content of the "bad-count" div.
    Output("live-graph", "figure"),  # Update the figure of the "live-graph" component.
    Output("packet-output", "children"),  # Update the content of the "packet-output" div.
    Input("interval", "n_intervals")  # Trigger updates whenever the "interval" component fires (every second).
)
def update_display(n):  # Define a callback function to update the dashboard. `n` represents the number of intervals elapsed.
    logs = packet_logs[-20:]  # Get the last 20 entries from the `packet_logs` list.
    log_divs = [
        html.Div(  # Create a div for each log entry.
            f"[{entry['time']}] {entry['type']} - {entry['summary']}",  # Format the log entry as "[timestamp] type - summary".
            style={
                "color": "green" if "Good" in entry['type'] else "red",  # Set the text color to green for good packets and red for bad packets.
                "fontWeight": "bold" if "Blocked" in entry['type'] else "normal"  # Set the font weight to bold for blocked packets and normal otherwise.
            }
        )
        for entry in logs  # Iterate over the last 20 log entries.
    ]
    return (
        str(good_count),  # Return the count of good packets as a string.
        str(bad_count),  # Return the count of bad packets as a string.
        {
            "data": [
                dict(x=packet_times[-20:], y=good_history[-20:], mode="lines+markers", name="Good", line={"color": "green"}),  # Plot the good packet counts over time. `x` is timestamps, `y` is counts, and `line` sets the color to green.
                dict(x=packet_times[-20:], y=bad_history[-20:], mode="lines+markers", name="Bad", line={"color": "red"})  # Plot the bad packet counts over time. `x` is timestamps, `y` is counts, and `line` sets the color to red.
            ],
            "layout": dict(title="Traffic Detection Over Time", xaxis={"title": "Time"}, yaxis={"title": "Packet Count"})  # Set the graph title and axis labels.
        },  # Return the updated graph figure.
        log_divs  # Return the formatted packet logs.
    )


@app.callback(
    Output("start-btn", "n_clicks"),  # Reset the click count of the "start-btn" button.
    Output("stop-btn", "n_clicks"),  # Reset the click count of the "stop-btn" button.
    Input("start-btn", "n_clicks"),  # Listen for clicks on the "start-btn" button.
    Input("stop-btn", "n_clicks"),  # Listen for clicks on the "stop-btn" button.
    State("start-btn", "n_clicks_timestamp"),  # Get the timestamp of the last click on the "start-btn" button.
    State("stop-btn", "n_clicks_timestamp")  # Get the timestamp of the last click on the "stop-btn" button.
)
def control_detection(start, stop, ts_start, ts_stop):  # Define a callback function to control packet simulation based on button clicks.
    global running  # Use the `global` keyword to modify the `running` flag.
    if ts_start and (not ts_stop or ts_start > ts_stop):  # If the "start-btn" was clicked more recently than the "stop-btn":
        running = True  # Set the `running` flag to True (start the simulation).
    elif ts_stop and (not ts_start or ts_stop > ts_start):  # If the "stop-btn" was clicked more recently than the "start-btn":
        running = False  # Set the `running` flag to False (stop the simulation).
    return start, stop  # Return the updated click counts for both buttons.


@server.route("/")  # Define the root route ("/") of the Flask server.
def home():  # Define a function to handle requests to the root route.
    return '<h2>Welcome to NIDS</h2><a href="/dashboard/">Open Dashboard</a>'  # Return an HTML response with a welcome message and a link to the dashboard.


# ========== Start the Application ========== #
if __name__ == '__main__':  # Check if the script is being run directly (not imported as a module).
    threading.Thread(target=packet_simulator, daemon=True).start()  # Start the packet simulator in a separate thread. `daemon=True` ensures the thread terminates when the main program exits.
    webbrowser.open("http://127.0.0.1:8050/dashboard/")  # Open the dashboard in the default web browser.
    server.run(debug=False, port=8050)  # Start the Flask server on port 8050. `debug=False` disables debug mode.