import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# -----------------------------
# Load trained model
# -----------------------------
model = joblib.load("phishing_model.pkl")


# -----------------------------
# Feature extraction
# -----------------------------
def extract_features(url):
    features = {}
    url = str(url)

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equals"] = url.count("=")
    features["num_at"] = url.count("@")
    features["num_ampersand"] = url.count("&")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["has_https"] = int(url.lower().startswith("https"))

    ip_pattern = r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}"
    features["has_ip"] = int(bool(re.search(ip_pattern, url)))

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        hostname = parsed.netloc

        features["hostname_length"] = len(hostname)
        features["num_subdomains"] = max(0, hostname.count(".") - 1)
        features["path_length"] = len(parsed.path)

    except:
        features["hostname_length"] = 0
        features["num_subdomains"] = 0
        features["path_length"] = 0

    return features


# -----------------------------
# Page design
# -----------------------------
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 PhishGuard")
st.subheader("Phishing URL Detection System")

st.write(
    "Enter a URL below to check whether it is potentially "
    "legitimate or phishing."
)

# -----------------------------
# URL input
# -----------------------------
url = st.text_input(
    "Enter URL",
    placeholder="https://example.com"
)


# -----------------------------
# Prediction
# -----------------------------
if st.button("🔍 Check URL"):

    if not url.strip():
        st.warning("Please enter a URL.")

    else:
        features = extract_features(url)

        input_data = pd.DataFrame([features])

        prediction = model.predict(input_data)[0]
        probability = model.predict_proba(input_data)[0]

        if prediction == 1:
            confidence = probability[1] * 100

            st.error("⚠️ PHISHING URL DETECTED")

            st.write(
                f"**Confidence:** {confidence:.2f}%"
            )

            st.warning(
                "Be careful! Do not enter passwords, "
                "banking information, or other sensitive data."
            )

        else:
            confidence = probability[0] * 100

            st.success("✅ LEGITIMATE URL")

            st.write(
                f"**Confidence:** {confidence:.2f}%"
            )

        st.write("### URL Checked")
        st.code(url)
