from flask import Flask, request, jsonify
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from joblib import load
from feature_extraction import extractFeatures
from flask_cors import CORS, cross_origin

# Load the trained Random Forest model
model_path = './model.joblib'  # Specify the path to the saved model
model = load(model_path)

# Initialize Flask application
app = Flask(__name__)
cors = CORS(app)

# Define a route for the prediction endpoint
@app.route('/predict', methods=['POST'])
@cross_origin()
def predict():
    # Get the input data from the request
    url = (request.get_json())['url']
    # Extract features from input url
    data = extractFeatures(url)
    # Convert the input data into a pandas DataFrame
    input_data = pd.DataFrame(data).T
    # Make predictions using the trained model
    predictions = model.predict(input_data)
    print(predictions[0])

    # Return the predictions as a JSON response
    response = {'predictions': predictions.tolist()}
    return jsonify(response)

# Run the Flask application
if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"))
