from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
import json
import requests
import re
import urllib.parse
import tldextract
import time
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

# Add the URLScan.io configuration
URLSCAN_API_KEY = 'e531f69c-0922-420a-bb32-e7084f6fcaaf'

# Add configuration for file uploads
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB in bytes
ALLOWED_PREVIEW_TYPES = ['.txt', '.md', '.html', '.htm']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/laws')
def laws():
    return render_template('laws.html')

@app.route('/helplines')
def helplines():
    return render_template('helplines.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/get_response', methods=['POST'])
def get_response():
    user_message = request.json.get('message', '')
    
    # Create a context for cybersecurity awareness
    prompt = f"""You are a Cybersecurity Awareness Chatbot. Your role is to educate users about 
    cybersecurity best practices and help them understand and avoid security threats. 
    Please provide helpful, accurate, and easy-to-understand responses. Ensure the response is always in HTML syntax. For bold, use <b> and </b> tags.
    for underline, use <u> and </u> tags. For italic, use <i> and </i> tags. For line break, use <br> tag. For header, always use <h3> and </h3> tags.
    User question: {user_message}"""
    
    try:
        url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaSyCDLGXbrPmqZJxaTQt2UIwd7TtGKu50ig8'
        api_key = os.getenv('GOOGLE_API_KEY')
        
        headers = {
            'Content-Type': 'application/json',
            'x-goog-api-key': api_key
        }
        
        data = {
            'contents': [{
                'parts': [{
                    'text': prompt
                }]
            }]
        }
        
        response = requests.post(url, headers=headers, json=data)
        print(response.json())
        if response.status_code == 200:
            result = response.json()
            text = result['candidates'][0]['content']['parts'][0]['text']
            print(text)
            return jsonify({'response': text})
        else:
            return jsonify({'response': f'Error: {response.status_code}'})
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'response': 'Sorry, I encountered an error. Please try again.'})

@app.route('/security-tools')
def security_tools():
    return render_template('security-tools.html')

@app.route('/check-password-strength', methods=['POST'])
def check_password_strength():
    password = request.json.get('password', '')
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
        feedback.append({"type": "success", "message": "Good length"})
    elif len(password) >= 8:
        score += 1
        feedback.append({"type": "warning", "message": "Consider using a longer password"})
    else:
        feedback.append({"type": "error", "message": "Password is too short"})

    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains uppercase letters"})
    else:
        feedback.append({"type": "error", "message": "Add uppercase letters"})

    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains lowercase letters"})
    else:
        feedback.append({"type": "error", "message": "Add lowercase letters"})

    # Numbers check
    if re.search(r'\d', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains numbers"})
    else:
        feedback.append({"type": "error", "message": "Add numbers"})

    # Special characters check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains special characters"})
    else:
        feedback.append({"type": "error", "message": "Add special characters"})

    # Calculate strength
    strength = ""
    if score < 2:
        strength = "Very Weak"
    elif score < 3:
        strength = "Weak"
    elif score < 4:
        strength = "Moderate"
    elif score < 5:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return jsonify({
        'score': score,
        'strength': strength,
        'feedback': feedback
    })

@app.route('/check-url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    
    risk_factors = []
    risk_level = "Low"
    
    try:
        parsed = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic checks
        if parsed.scheme != 'https':
            risk_factors.append("Not using HTTPS (secure connection)")
            risk_level = "High"
            
        if any(extracted.suffix.endswith(tld) for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf']):
            risk_factors.append("Suspicious domain extension")
            risk_level = "High"
            
        if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain):
            risk_factors.append("Using IP address instead of domain name")
            risk_level = "High"

        # URLScan.io integration
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        
        scan_payload = {
            "url": url,
            "visibility": "public",
            "tags": ["phishing_check", "demo"]
        }
        
        # Submit URL for scanning
        submission = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=scan_payload
        )
        
        if submission.status_code == 200:
            scan_uuid = submission.json().get("uuid")
            
            # Wait for scan to complete
            time.sleep(5)  # Wait for scan to process
            
            # Get scan results
            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            result = requests.get(result_url)
            print(result.json())
            if result.status_code == 200:
                result_data = result.json()
                
                # Check malicious verdict
                if result_data.get("verdicts", {}).get("overall", {}).get("malicious"):
                    risk_factors.append("URL flagged as malicious by URLScan.io")
                    risk_level = "High"
                
                # Check for suspicious technologies
                tech = result_data.get("page", {}).get("technologies", [])
                suspicious_tech = ["phishing", "spam", "malware"]
                if any(t.lower() in str(tech).lower() for t in suspicious_tech):
                    risk_factors.append("Suspicious technologies detected")
                    risk_level = "High"
        
        if not risk_factors:
            risk_factors.append("No obvious risk factors detected")
            
    except Exception as e:
        print(f"Error scanning URL: {str(e)}")
        risk_factors.append("Error during URL scan")
        risk_level = "Unknown"
    
    return jsonify({
        'risk_level': risk_level,
        'risk_factors': risk_factors
    })

@app.route('/encryption-tools')
def encryption_tools():
    return render_template('encryption-tools.html')

@app.route('/generate-key', methods=['POST'])
def generate_key():
    key_type = request.json.get('type', 'aes')
    if key_type == 'aes':
        key = get_random_bytes(16)  # 128 bits for AES
    else:
        key = get_random_bytes(8)   # 64 bits for DES
    return jsonify({'key': base64.b64encode(key).decode()})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        if not data.get('text'):
            return jsonify({'success': False, 'error': 'Missing text to encrypt'})

        text = data['text'].encode('utf-8')
        algorithm = data.get('algorithm', 'aes')

        # Generate new key if not provided
        if not data.get('key'):
            key = get_random_bytes(16 if algorithm == 'aes' else 8)
            key_b64 = base64.b64encode(key).decode('utf-8')
        else:
            try:
                key = base64.b64decode(data['key'])
                key_b64 = data['key']
            except:
                return jsonify({'success': False, 'error': 'Invalid key format'})

        # Validate key sizes
        if algorithm == 'aes' and len(key) != 16:
            return jsonify({'success': False, 'error': 'Invalid AES key size'})
        elif algorithm == 'des' and len(key) != 8:
            return jsonify({'success': False, 'error': 'Invalid DES key size'})

        if algorithm == 'aes':
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text, AES.block_size))
        else:
            cipher = DES.new(key, DES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text, DES.block_size))

        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')

        return jsonify({
            'success': True,
            'ciphertext': ct,
            'iv': iv,
            'key': key_b64  # Return key only if newly generated
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        # Ensure we're getting all required parameters
        if not all([data.get('ciphertext'), data.get('key'), data.get('iv')]):
            return jsonify({'success': False, 'error': 'Missing required parameters'})

        try:
            # Properly decode the input parameters
            ciphertext = base64.b64decode(data['ciphertext'])
            key = base64.b64decode(data['key'])
            iv = base64.b64decode(data['iv'])
            algorithm = data.get('algorithm', 'aes')
        except Exception as e:
            return jsonify({'success': False, 'error': f'Invalid input format: {str(e)}'})

        # Validate key sizes
        if algorithm == 'aes' and len(key) != 16:  # AES-128
            return jsonify({'success': False, 'error': 'Invalid AES key size'})
        elif algorithm == 'des' and len(key) != 8:  # DES
            return jsonify({'success': False, 'error': 'Invalid DES key size'})

        try:
            if algorithm == 'aes':
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
            else:
                cipher = DES.new(key, DES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ciphertext), DES.block_size)

            return jsonify({
                'success': True,
                'plaintext': pt.decode('utf-8')
            })

        except ValueError as ve:
            return jsonify({'success': False, 'error': f'Decryption error: {str(ve)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'})

@app.route('/check-file', methods=['POST'])
def check_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > MAX_FILE_SIZE:
        return jsonify({'error': 'File size exceeds 1 MB limit'})
    
    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()
    
    # Read file content for preview if allowed type
    preview = None
    if file_ext in ALLOWED_PREVIEW_TYPES:
        try:
            preview = file.read().decode('utf-8')
        except:
            preview = "Unable to preview file content"
    
    return jsonify({
        'name': filename,
        'size': size,
        'preview': preview,
        'canPreview': file_ext in ALLOWED_PREVIEW_TYPES
    })

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        key = base64.b64decode(request.form.get('key', ''))
        algorithm = request.form.get('algorithm', 'aes')
        
        # Read file content as bytes
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        if algorithm == 'aes':
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(file_content, AES.block_size))
        else:
            cipher = DES.new(key, DES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(file_content, DES.block_size))
            
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        
        return jsonify({
            'success': True,
            'ciphertext': ct,
            'iv': iv,
            'filename': filename
        })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        key = base64.b64decode(request.form.get('key', ''))
        iv = base64.b64decode(request.form.get('iv', ''))
        algorithm = request.form.get('algorithm', 'aes')
        
        # Read encrypted content
        file_content = file.read()
        
        # Try to decode if it's base64 encoded text
        try:
            encrypted_content = base64.b64decode(file_content)
        except:
            # If not base64, use the raw content
            encrypted_content = file_content
        
        if algorithm == 'aes':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        else:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(encrypted_content), DES.block_size)
            
        # Try to decode as text
        try:
            plaintext = pt.decode('utf-8', errors='strict')
            return jsonify({
                'success': True,
                'plaintext': plaintext,
                'is_text': True,
                'raw_data': base64.b64encode(pt).decode('utf-8')  # Include raw data for both text and binary
            })
        except UnicodeDecodeError:
            # If it's not text content, return as base64
            return jsonify({
                'success': True,
                'plaintext': base64.b64encode(pt).decode('utf-8'),
                'is_text': False,
                'raw_data': base64.b64encode(pt).decode('utf-8')
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/scan-url', methods=['POST'])
def scan_url():
    try:
        url = request.json.get('url', '')
        
        # Basic URL validation
        if not url:
            return jsonify({
                'safe': False,
                'message': 'Please enter a URL'
            })

        # Add http:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Parse and validate URL
        parsed = urllib.parse.urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return jsonify({
                'safe': False,
                'message': 'Invalid URL format'
            })

        # Extract domain information
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"

        # Initialize security checks
        security_issues = []
        risk_level = "low"
        
        # Check for common suspicious patterns
        suspicious_patterns = [
            r'login.*\.php',
            r'secure.*\.php',
            r'account.*\.php',
            r'banking.*\.php',
            r'paypal.*\.php',
            r'wallet.*\.php',
            r'bitcoin.*\.php',
            r'\d{10,}',  # Long numbers
            r'[a-zA-Z0-9]{32,}',  # Long random strings
            r'verify.*account',
            r'confirm.*payment',
            r'update.*billing'
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url.lower()):
                security_issues.append("Suspicious URL pattern detected")
                risk_level = "high"
        
        # Check HTTPS
        is_https = url.startswith('https://')
        if not is_https:
            security_issues.append("Website doesn't use HTTPS encryption")
            risk_level = "high"
        
        # Check for suspicious TLD
        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            security_issues.append("Suspicious domain extension")
            risk_level = "high"
        
        # Check for IP address as domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain_info.domain):
            security_issues.append("Using IP address instead of domain name")
            risk_level = "high"
        
        # Try to fetch the URL to check if it exists
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code >= 400:
                security_issues.append("Website appears to be unavailable")
        except:
            security_issues.append("Unable to connect to website")
        
        # Prepare response message
        if not security_issues:
            message = "No obvious security issues detected. However, always be cautious when sharing sensitive information online."
            is_safe = True
        else:
            message = "Security concerns: " + "; ".join(security_issues)
            is_safe = False
        
        return jsonify({
            'safe': is_safe,
            'message': message,
            'risk_level': risk_level
        })

    except Exception as e:
        print(f"Error scanning URL: {str(e)}")
        return jsonify({
            'safe': False,
            'message': f'Error scanning URL: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(debug=True,port=5002) 