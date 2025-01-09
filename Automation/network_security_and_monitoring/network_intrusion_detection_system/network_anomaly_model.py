from sklearn.ensemble import RandomForestClassifier
import joblib
import pandas as pd
import socket
import struct
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Convert IP addr to integers
def ip_to_int(ip):
    return int(socket.ntohl(struct.unpack('I', socket.inet_aton(ip))[0]))

# Load dataset
data = pd.read_csv("/home/udeh/Desktop/python_automation_for_cybersecurity/Automation/network_security_and_monitoring/network_intrusion_detection_system/network_traffic.csv")

# Convert IP columns to integers (if applicable)
if 'ip_address' in data.columns:
    data['ip_address'] = data['ip_address'].apply(ip_to_int)

# Handle categorical columns (if any)
label_encoder = LabelEncoder()
for column in data.select_dtypes(include=["object"]).columns:
    data[column] = label_encoder.fit_transform(data[column])

# Split dataset into features and labels
X = data.drop(columns=["label"])  # Features
y = data["label"]  # Labels: 0 for normal, 1 for anomaly

# Handle missing data (if any)
X = X.dropna()
y = y.dropna()

# Split the dataset into training and testing sets (optional but recommended)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest Classifier
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save the trained model
joblib.dump(model, "/home/udeh/Desktop/python_automation_for_cybersecurity/Automation/network_security_and_monitoring/network_intrusion_detection_system/network_anomaly_model.pkl")
print("Model trained and saved as network_anomaly_model.pkl.")
