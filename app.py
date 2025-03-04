from flask import Flask, request, render_template, jsonify
import pandas as pd
import tensorflow as tf
import requests
from urllib.parse import urlparse
import re
import ipaddress
import dns.resolver
import numpy as np

app = Flask(__name__)

# Load the trained model
#model = tf.keras.models.load_model("model1_TDLHBA.h5")

TFLITE_MODEL_PATH = "model1_TDLHBA.tflite"

# Load TFLite model into an interpreter
interpreter = tf.lite.Interpreter(model_path=TFLITE_MODEL_PATH)
interpreter.allocate_tensors()

# Get input and output tensor indices
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()


# Feature extraction functions
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    return urlparse(url).path.count('/')

def redirection(url):
    return 1 if '//' in url[7:] else 0

def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

def tinyURL(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl"
    return 1 if re.search(shortening_services, url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def check_dns(url):
    try:
        domain = urlparse(url).netloc
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.resolve(domain, 'A')
        return 1
    except:
        return 0

# 12.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        # Filling whitespaces in the URL if any
        url = urllib.parse.quote(url)
        response = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url)
        soup = BeautifulSoup(response.read(), "xml")
        rank = int(soup.find("REACH")['RANK'])
        
        # Check if the rank is less than 100,000
        if rank < 100000:
            return 1
        else:
            return 0
    except Exception:
        # Return 1 in case of an error to match the original first function's behavior
        return 1

from urllib.parse import urlparse

# List of newer TLDs that are commonly associated with new domains
new_tlds = ['xyz', 'club', 'top', 'online', 'win', 'xyz', 'tech', 'site', 'click', 'icu']

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(url):
    try:
        # Extract the domain from the URL
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]  # Remove 'www.' if it exists
        
        # Extract the TLD (Top-Level Domain) from the domain
        tld = domain.split('.')[-1]
        
        # If the TLD is in the list of known "new" TLDs, return 0 (new domain)
        if tld in new_tlds:
            return 0  # New domain
        
        # Otherwise, return 1 (older domain)
        return 1  # Older domain
    
    except Exception as e:
        # If an error occurs (e.g., invalid URL), return 1
        return 1


# 14.End time of domain: The difference between termination time and current time (Domain_End) 
from urllib.parse import urlparse
from datetime import datetime

# List of TLDs commonly associated with short-lived or newer domains
short_lived_tlds = ['xyz', 'club', 'top', 'online', 'click', 'icu']

def domainEnd(url):
    try:
        # Extract the domain from the URL
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]  # Remove 'www.' if it exists
        
        # Extract the TLD (Top-Level Domain) from the domain
        tld = domain.split('.')[-1]
        
        # Check if the TLD is in the list of short-lived domains
        if tld in short_lived_tlds:
            return 0  # Assumed to be a domain with a short lifespan (likely to expire soon)
        
        # If the domain's TLD is not in the short-lived TLD list, assume it has a longer lifespan
        return 1  # Assume it will be renewed and doesn't expire soon
    
    except Exception as e:
        # If an error occurs (e.g., invalid URL), return 1
        return 1


def iframe(url):
    try:
        response = requests.get(url, timeout=5)
        response_text = response.text
    except requests.RequestException:
        return 1
    return 0 if re.findall(r"<iframe>|<frameBorder>", response_text) else 1

# def mouseOver(url):
#     try:
#         response = requests.get(url, timeout=5)
#         response_text = response.text
#     except requests.RequestException:
#         return 1
#     return 1 if re.findall("<script>.+onmouseover.+</script>", response_text) else 0

def mouseOver(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url)
            
            page_source = page.content()
            browser.close()

            return 1 if re.findall("<script>.+onmouseover.+</script>", page_source) else 0
    except Exception as e:
        print("MouseOver Error:", e)
        return 1

def rightClick(url):
    try:
        response = requests.get(url, timeout=5)
        response_text = response.text
    except requests.RequestException:
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response_text) else 1

# def forwarding(url):
#     try:
#         response = requests.get(url, timeout=5)
#     except requests.RequestException:
#         return 1
#     return 0 if len(response.history) <= 2 else 1

def forwarding(url):
    try:
        options = Options()
        options.add_argument("--headless")
        driver = webdriver.Chrome(options=options)
        driver.get(url)

        # Check if the current URL is different from the original URL
        final_url = driver.current_url
        driver.quit()

        return 1 if final_url != url else 0
    except Exception as e:
        print("Forwarding Error:", e)
        return 1

# Extract Features from URL
def featureExtraction(url):
    features = [
        havingIP(url), haveAtSign(url), getLength(url), getDepth(url),
        redirection(url), httpDomain(url), tinyURL(url), prefixSuffix(url),
        check_dns(url), web_traffic(url), domainAge(url), domainEnd(url),
        iframe(url), mouseOver(url), rightClick(url), forwarding(url),
    ]
    
    feature_names = [
        "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
        "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record",
        "Web_Traffic", "Domain_Age", "Domain_End", "iFrame", "Mouse_Over",
        "Right_Click", "Web_Forwards"
    ]
    
    feature_dict = {name: value for name, value in zip(feature_names, features)}
    return feature_dict



# Generate explanation based on feature extraction
def generate_explanation(features):
    reasons = []

    if features["Have_IP"] == 1:
        reasons.append("The URL contains an IP address instead of a domain, which is common in phishing attempts.")
    if features["Have_At"] == 1:
        reasons.append("The URL contains '@', which can be used to trick users into visiting a fake website.")
    if features["URL_Length"] == 1:
        reasons.append("The URL is unusually long, which can be a tactic to hide malicious links.")
    if features["URL_Depth"] > 4:
        reasons.append("The URL has many directory levels, which is sometimes used to mimic legitimate sites.")
    if features["Redirection"] == 1:
        reasons.append("The URL has multiple redirections ('//'), which can hide phishing behavior.")
    if features["TinyURL"] == 1:
        reasons.append("The URL is shortened using a service like bit.ly, making it harder to verify the real destination.")
    if features["Prefix/Suffix"] == 1:
        reasons.append("The domain contains a '-' symbol, which is often used in fake websites.")
    if features["DNS_Record"] == 0:
        reasons.append("The domain does not have a valid DNS record, meaning it may not be legitimate.")
    if features["Mouse_Over"] == 1:
        reasons.append("The webpage contains JavaScript that changes the status bar when hovering over a link, a phishing trick.")
    if features["Right_Click"] == 0:
        reasons.append("The website has disabled right-click, which is used to prevent users from inspecting the webpage.")
    if features["Web_Forwards"] == 1:
        reasons.append("The webpage has multiple forwarding links, often used in phishing scams.")

    if not reasons:
        reasons.append("No significant phishing indicators detected. The URL appears safe.")

    return reasons



def predict_with_tflite(features_df):
    # Convert DataFrame to NumPy array and reshape
    input_data = np.array(features_df, dtype=np.float32).reshape(1, -1)

    # Set the input tensor
    interpreter.set_tensor(input_details[0]['index'], input_data)

    # Run the model
    interpreter.invoke()

    # Get the prediction result
    output_data = interpreter.get_tensor(output_details[0]['index'])

    # Convert output to a readable format
    prediction = "Phishing" if output_data[0][0] >= 0.5 else "Legitimate"
    return prediction



@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        extracted_features = featureExtraction(url)
        
        # Convert feature dict to DataFrame
        features_df = pd.DataFrame([list(extracted_features.values())], columns=extracted_features.keys())
        features_df = features_df.astype("float32")

        # Make prediction
        prediction = predict_with_tflite(features_df)
        # result = "Phishing" if prediction[0] >= 0.5 else "Legitimate"

        explanation = generate_explanation(extracted_features)

        return render_template("index.html", url=url, prediction=prediction, extracted_features=extracted_features, explanation=explanation)

    return render_template("index.html", url="", prediction="", extracted_features={}, explanation=[])

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
