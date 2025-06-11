from flask import Blueprint, request, jsonify
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

prediction_bp = Blueprint('prediction', __name__)

# Load the trained model and preprocessors
model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'random_forest_model.pkl')
scaler_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'scaler.pkl')
le_source_ip_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'le_source_ip.pkl')
le_dest_ip_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'le_dest_ip.pkl')

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)
le_source_ip = joblib.load(le_source_ip_path)
le_dest_ip = joblib.load(le_dest_ip_path)

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        
        # Create a DataFrame from the input data
        df = pd.DataFrame([data])
        
        # Handle categorical features
        # For new IPs not seen during training, assign a default value
        try:
            df['Source IP'] = le_source_ip.transform(df['Source IP'])
        except ValueError:
            df['Source IP'] = 0  # Default value for unseen IPs
            
        try:
            df['Destination IP'] = le_dest_ip.transform(df['Destination IP'])
        except ValueError:
            df['Destination IP'] = 0  # Default value for unseen IPs
        
        # Handle infinite values
        df.replace([float('inf'), -float('inf')], 0, inplace=True)
        df.fillna(0, inplace=True)
        
        # Scale the features
        X_scaled = scaler.transform(df)
        
        # Make prediction
        prediction = model.predict(X_scaled)[0]
        probability = model.predict_proba(X_scaled)[0]
        
        # Get the probability for each class
        classes = model.classes_
        prob_dict = {classes[i]: float(probability[i]) for i in range(len(classes))}
        
        return jsonify({
            'prediction': prediction,
            'probabilities': prob_dict,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 400

@prediction_bp.route('/predict_simple', methods=['POST'])
def predict_simple():
    """Simplified prediction endpoint with fewer required fields"""
    try:
        data = request.get_json()
        
        # Create a simplified feature vector with default values
        # This is a simplified version for demo purposes
        feature_dict = {
            'Source IP': data.get('source_ip', '192.168.1.1'),
            'Source Port': int(data.get('source_port', 80)),
            'Destination IP': data.get('destination_ip', '192.168.1.2'),
            'Destination Port': int(data.get('destination_port', 443)),
            'Protocol': int(data.get('protocol', 6)),
            'Flow Duration': int(data.get('flow_duration', 1000)),
            'Total Fwd Packets': int(data.get('total_fwd_packets', 10)),
            'Total Backward Packets': int(data.get('total_backward_packets', 8)),
            'Total Length of Fwd Packets': int(data.get('total_length_fwd_packets', 1500)),
            'Total Length of Bwd Packets': int(data.get('total_length_bwd_packets', 1200)),
        }
        
        # Fill remaining features with default values (simplified for demo)
        default_features = {
            'Fwd Packet Length Max': 1500, 'Fwd Packet Length Min': 0, 'Fwd Packet Length Mean': 150.0, 'Fwd Packet Length Std': 50.0,
            'Bwd Packet Length Max': 1200, 'Bwd Packet Length Min': 0, 'Bwd Packet Length Mean': 150.0, 'Bwd Packet Length Std': 50.0,
            'Flow Bytes/s': 1000.0, 'Flow Packets/s': 10.0, 'Flow IAT Mean': 100.0, 'Flow IAT Std': 50.0, 'Flow IAT Max': 200.0, 'Flow IAT Min': 0.0,
            'Fwd IAT Total': 1000.0, 'Fwd IAT Mean': 100.0, 'Fwd IAT Std': 50.0, 'Fwd IAT Max': 200.0, 'Fwd IAT Min': 0.0,
            'Bwd IAT Total': 800.0, 'Bwd IAT Mean': 100.0, 'Bwd IAT Std': 50.0, 'Bwd IAT Max': 200.0, 'Bwd IAT Min': 0.0,
            'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Header Length': 32, 'Bwd Header Length': 32,
            'Fwd Packets/s': 5.0, 'Bwd Packets/s': 4.0, 'Min Packet Length': 0, 'Max Packet Length': 1500, 'Packet Length Mean': 150.0, 'Packet Length Std': 50.0, 'Packet Length Variance': 2500.0,
            'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 1, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0, 'Down/Up Ratio': 0,
            'Average Packet Size': 150.0, 'Avg Fwd Segment Size': 150.0, 'Avg Bwd Segment Size': 150.0, 'Fwd Header Length.1': 32,
            'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': 10, 'Subflow Fwd Bytes': 1500, 'Subflow Bwd Packets': 8, 'Subflow Bwd Bytes': 1200,
            'Init_Win_bytes_forward': 29200, 'Init_Win_bytes_backward': 243, 'act_data_pkt_fwd': 5, 'min_seg_size_forward': 32,
            'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0.0, 'Active Min': 0.0,
            'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0.0, 'Idle Min': 0.0
        }
        
        # Merge user input with defaults
        feature_dict.update(default_features)
        
        # Create DataFrame
        df = pd.DataFrame([feature_dict])
        
        # Handle categorical features
        try:
            df['Source IP'] = le_source_ip.transform(df['Source IP'])
        except ValueError:
            df['Source IP'] = 0
            
        try:
            df['Destination IP'] = le_dest_ip.transform(df['Destination IP'])
        except ValueError:
            df['Destination IP'] = 0
        
        # Handle infinite values
        df.replace([float('inf'), -float('inf')], 0, inplace=True)
        df.fillna(0, inplace=True)
        
        # Scale the features
        X_scaled = scaler.transform(df)
        
        # Make prediction
        prediction = model.predict(X_scaled)[0]
        probability = model.predict_proba(X_scaled)[0]
        
        # Get the probability for each class
        classes = model.classes_
        prob_dict = {classes[i]: float(probability[i]) for i in range(len(classes))}
        
        return jsonify({
            'prediction': prediction,
            'probabilities': prob_dict,
            'status': 'success',
            'message': f'Network traffic classified as: {prediction}'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 400

