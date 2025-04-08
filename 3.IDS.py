# Import necessary libraries
import os  # For interacting with the operating system (file search)
import pandas as pd  # For data manipulation and analysis
import numpy as np  # For numerical operations
import joblib  # For saving and loading machine learning models (not used in this script)
import threading  # For running tasks concurrently
import time  # For introducing delays in execution
import datetime  # For working with date and time
import webbrowser  # For opening the browser automatically
from flask import Flask as FlaskBase  # For creating a Flask server
from dash import Dash, html, dcc, Input, Output, ctx  # For building the Dash application
import plotly.graph_objs as go  # For creating interactive plots
from sklearn.ensemble import RandomForestClassifier  # For building a random forest model
from sklearn.model_selection import train_test_split  # For splitting the dataset into training and testing sets
from sklearn.preprocessing import LabelEncoder  # For encoding categorical variables
import dash_bootstrap_components as dbc  # For using Bootstrap components in Dash

# Initialize Flask and Dash
server = FlaskBase(__name__)  # Create a Flask server instance
app = Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP])  # Create a Dash app with Bootstrap styling

# Define column names for the dataset
columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
           "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
           "root_shell","su_attempted","num_root","num_file_creations","num_shells",
           "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
           "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
           "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
           "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
           "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
           "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]

# Search for the dataset file
kdd_filename = "KDDTrain+.txt"  # Name of the dataset file
dataset_path = None  # Variable to store the path of the dataset
for root, dirs, files in os.walk("C:\\"):  # Traverse through all directories in the C drive
    if kdd_filename in files:  # Check if the dataset file exists in the current directory
        dataset_path = os.path.join(root, kdd_filename)  # Store the full path of the dataset
        break  # Exit the loop once the dataset is found
    if dataset_path:
        break  # Exit the loop if the dataset path is already set

if not dataset_path:  # If the dataset was not found
    raise FileNotFoundError("KDDTrain+.txt not found in the C drive")  # Raise an error

# Load the dataset and adjust the column length
df = pd.read_csv(dataset_path, header=None)  # Read the dataset without headers
if len(df.columns) > len(columns):  # If the dataset has more columns than expected
    df = df.iloc[:, :len(columns)]  # Truncate the dataset to match the expected number of columns
if len(df.columns) < len(columns):  # If the dataset has fewer columns than expected
    columns = columns[:len(df.columns)]  # Adjust the column names to match the dataset
df.columns = columns  # Assign the column names to the dataset

# Preprocess the data
le = LabelEncoder()  # Initialize a label encoder for encoding categorical variables
if 'label' in df.columns:  # Check if the 'label' column exists in the dataset
    df['label'] = le.fit_transform(df['label'])  # Encode the 'label' column
    label_mapping = dict(zip(le.classes_, le.transform(le.classes_)))  # Create a mapping of original labels to encoded values
    normal_label = label_mapping.get('normal', None)  # Get the encoded value for the 'normal' label
    if normal_label is None:  # If the 'normal' label is not found
        raise ValueError("'normal' label not found in dataset")  # Raise an error
else:
    raise ValueError("'label' column not found in dataset")  # Raise an error if the 'label' column is missing

for col in df.select_dtypes(include='object').columns:  # Iterate over all object-type columns
    if col != 'label':  # Exclude the 'label' column
        df[col] = le.fit_transform(df[col])  # Encode the categorical column

X = df.drop("label", axis=1)  # Drop the 'label' column to create feature matrix
y = df["label"]  # Extract the 'label' column as the target variable

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)  # Split the dataset into training and testing sets
model = RandomForestClassifier(n_jobs=-1, n_estimators=100)  # Initialize a random forest classifier
model.fit(X_train, y_train)  # Train the model on the training data

# Detection variables
detecting = False  # Boolean flag to indicate whether detection is active
good_packets = []  # List to store good packets
bad_packets = []  # List to store bad packets
alert_messages = []  # List to store alert messages
packet_data = []  # List to store packet data for visualization
data_lock = threading.Lock()  # Thread lock to ensure thread-safe access to shared data

# UI Layout
app.layout = html.Div([  # Define the layout of the Dash application
    html.H1("Intrusion Detection System", style={'textAlign': 'center'}),  # Title of the application
    html.Div([  # Container for buttons
        html.Button("Start Detecting", id="start-button", n_clicks=0, className='btn btn-success me-2'),  # Start button
        html.Button("Stop Detecting", id="stop-button", n_clicks=0, className='btn btn-danger'),  # Stop button
    ], style={'textAlign': 'center', 'marginBottom': '20px'}),  # Center-align buttons and add margin

    html.Div([  # Container for packet counts, graph, and alerts
        html.Div(id="packet-counts", style={"textAlign": "center", "fontSize": 20, 'marginBottom': '20px'}),  # Packet count display
        dcc.Graph(id="live-graph"),  # Live graph for visualizing packet data
        dcc.Interval(id="interval-component", interval=2000, n_intervals=0),  # Interval component for periodic updates
        html.Div(id="alerts", style={"textAlign": "left", "marginTop": "20px", "whiteSpace": "pre-line"})  # Alerts display
    ])
])

# Packet Simulation Function
def simulate_packets():  # Function to simulate packet detection
    global detecting  # Use the global 'detecting' flag
    while detecting:  # Run the simulation loop while detection is active
        with data_lock:  # Acquire the thread lock to ensure thread-safe access
            packet_row = X.sample(1)  # Randomly sample a row from the feature matrix
            packet = packet_row.values[0]  # Extract the packet data as a NumPy array
            prediction = model.predict(packet_row)[0]  # Predict the label for the packet
            ip_src = f"192.168.0.{np.random.randint(1, 255)}"  # Generate a random source IP address
            ip_dst = f"10.0.0.{np.random.randint(1, 255)}"  # Generate a random destination IP address

            timestamp = datetime.datetime.now().strftime('%H:%M:%S')  # Get the current timestamp
            if prediction == normal_label:  # If the packet is classified as 'normal'
                good_packets.append(packet)  # Add the packet to the list of good packets
                msg = html.Div([  # Create an alert message for a good packet
                    html.Span(f"{timestamp} \U0001F7E2 ", style={"fontWeight": "bold", "color": "green"}),  # Timestamp with green circle
                    html.Span(f"GOOD PACKET: From {ip_src} to {ip_dst}", style={"color": "green", "fontWeight": "bold"})  # Packet details
                ])
            else:  # If the packet is classified as malicious
                bad_packets.append(packet)  # Add the packet to the list of bad packets
                msg = html.Div([  # Create an alert message for a bad packet
                    html.Span(f"{timestamp} \U0001F534 ", style={"fontWeight": "bold", "color": "red"}),  # Timestamp with red circle
                    html.Span(f"BLOCKED BAD PACKET: From {ip_src} to {ip_dst}", style={"color": "red", "fontWeight": "bold"})  # Packet details
                ])

            alert_messages.append(msg)  # Add the alert message to the list
            packet_data.append({  # Add the packet data to the list for visualization
                "time": timestamp,
                "good": len(good_packets),
                "bad": len(bad_packets)
            })
        time.sleep(0.5)  # Introduce a delay between packets

# Start/Stop Button Callbacks
@app.callback(  # Define a callback for the start and stop buttons
    Output("start-button", "disabled"),  # Disable or enable the start button
    Output("stop-button", "disabled"),  # Disable or enable the stop button
    Input("start-button", "n_clicks"),  # Listen for clicks on the start button
    Input("stop-button", "n_clicks")  # Listen for clicks on the stop button
)
def toggle_detection(start_clicks, stop_clicks):  # Function to toggle detection
    global detecting  # Use the global 'detecting' flag
    if ctx.triggered_id == "start-button":  # If the start button was clicked
        detecting = True  # Set the detection flag to True
        threading.Thread(target=simulate_packets, daemon=True).start()  # Start the packet simulation in a new thread
        return True, False  # Disable the start button and enable the stop button
    elif ctx.triggered_id == "stop-button":  # If the stop button was clicked
        detecting = False  # Set the detection flag to False
        return False, True  # Enable the start button and disable the stop button
    return False, True  # Default state: start button enabled, stop button disabled

# Packet Count Display
@app.callback(  # Define a callback for updating packet counts
    Output("packet-counts", "children"),  # Update the packet count display
    Input("interval-component", "n_intervals")  # Listen for updates from the interval component
)
def update_counts(n):  # Function to update packet counts
    with data_lock:  # Acquire the thread lock to ensure thread-safe access
        return f"Good Packets: {len(good_packets)} | Bad Packets: {len(bad_packets)}"  # Return the updated packet counts

# Alerts Update
@app.callback(  # Define a callback for updating alerts
    Output("alerts", "children"),  # Update the alerts display
    Input("interval-component", "n_intervals")  # Listen for updates from the interval component
)
def update_alerts(n):  # Function to update alerts
    with data_lock:  # Acquire the thread lock to ensure thread-safe access
        return alert_messages[-10:]  # Return the last 10 alert messages

# Live Graph Update
@app.callback(  # Define a callback for updating the live graph
    Output("live-graph", "figure"),  # Update the live graph
    Input("interval-component", "n_intervals")  # Listen for updates from the interval component
)
def update_graph(n):  # Function to update the live graph
    with data_lock:  # Acquire the thread lock to ensure thread-safe access
        if not packet_data:  # If no packet data is available
            return go.Figure(layout=go.Layout(title="Waiting for packet data..."))  # Return an empty graph with a waiting message
        times = [d["time"] for d in packet_data]  # Extract timestamps from packet data
        good_counts = [d["good"] for d in packet_data]  # Extract good packet counts
        bad_counts = [d["bad"] for d in packet_data]  # Extract bad packet counts

    fig = go.Figure()  # Create a new figure
    fig.add_trace(go.Scatter(x=times, y=good_counts, mode='lines+markers', name='Good Packets', line=dict(color='green')))  # Add good packet trace
    fig.add_trace(go.Scatter(x=times, y=bad_counts, mode='lines+markers', name='Bad Packets', line=dict(color='red')))  # Add bad packet trace
    fig.update_layout(title="Live Packet Detection", xaxis_title="Time", yaxis_title="Count")  # Update the graph layout
    return fig  # Return the updated graph

# Auto-launch browser and run app
def open_browser():  # Function to open the browser automatically
    webbrowser.open_new("http://127.0.0.1:8050")  # Open the Dash app in the default browser

if __name__ == '__main__':  # Check if the script is being run directly
    threading.Timer(1.0, open_browser).start()  # Schedule the browser to open after 1 second
    app.run(debug=False, port=8050)  # Run the Dash app on port 8050 without debug mode
