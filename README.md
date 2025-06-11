# APT-ScanDetector
AI-powered NIDS using Random Forest to detect APT scanning attacks. Features a Flask web app for real-time network analysis with AI predictions and confidence indicators. Supports binary classification (BENIGN vs. PortScan) with modern UI/UX. Built with Python, Flask, Scikit-learn, and Pandas
APT-ScanDetector is an AI-driven Network Intrusion Detection System (NIDS) designed to identify Advanced Persistent Threat (APT) scanning attacks. By leveraging a Random Forest Classifier, it classifies network traffic into BENIGN or PortScan categories, ensuring accurate and early detection of malicious reconnaissance activity.

This system utilizes a labeled dataset containing network traffic features such as packet counts, flow duration, IP addresses, and protocols. Feature selection focuses on the most relevant attributes for effective model training. The Random Forest model offers high accuracy (~99% training, ~98% testing) and reliability, supported by metrics like precision (97%) and recall (96%) for PortScan detection.

APT-ScanDetector is built as a Flask-based web application, providing a clean and intuitive interface. Users can input network traffic details and receive real-time AI-generated predictions, complete with confidence scores and visual indicators. The responsive frontend (HTML, CSS) features modern UI/UX design principles, including dynamic probability bars and color-coded results (green for BENIGN, red for PortScan).

The backend, developed in Python, integrates the trained machine learning model with preprocessing logic, ensuring seamless communication between the user interface and prediction module. Key routes include /api/predict_simple for submitting traffic details and receiving JSON responses. The application also includes robust error handling and input validation.

Designed with accessibility and practicality in mind, APT-ScanDetector empowers cybersecurity professionals and network administrators to identify potential threats in real-time without requiring deep technical expertise. Its lightweight architecture and comprehensive deployment documentation make it easy to test and expand for broader use cases.

Key Features:

AI-powered detection of APT scanning attacks using Random Forest.

Real-time network traffic analysis with intuitive confidence indicators.

Flask-based web app with modern UI/UX for enhanced usability.

Lightweight and extensible architecture for local or cloud deployment.

Technologies: Python, Flask, Scikit-learn, Pandas, HTML, CSS.

APT-ScanDetector bridges the gap between cutting-edge AI technology and practical cybersecurity needs.
