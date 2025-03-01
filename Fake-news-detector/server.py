from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import logging

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
classifier = joblib.load('./model/pipeline.pkl')

# Configure logging
logging.basicConfig(level=logging.INFO)

@app.before_request
def log_request_info():
    app.logger.info('Request: %s %s', request.method, request.url)
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())

# @app.route('/')
# def hello_world():
#     return 'Hello, World!'

@app.route('/predict', methods=['POST'])
def predict():
    json_ = request.json

    prediction = classifier.predict(json_['text']).tolist()
    return jsonify({'prediction': prediction[0] })

if __name__ == '__main__':
    classifier = joblib.load('./model/pipeline.pkl')
    app.run(port=5005,host="0.0.0.0")
