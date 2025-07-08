# app.py
from flask import Flask, request, render_template, send_file, redirect, url_for
from lxml import etree
from signxml import XMLSigner, methods
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SIGNED_FOLDER'] = 'signed'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SIGNED_FOLDER'], exist_ok=True)

PRIVATE_KEY_PATH = "certs/private_key.pem"
CERTIFICATE_PATH = "certs/certificate.pem"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'xmlfile' not in request.files:
            return "No file part", 400

        file = request.files['xmlfile']
        if file.filename == '':
            return "No selected file", 400

        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        output_path = os.path.join(app.config['SIGNED_FOLDER'], f"signed_{filename}")

        try:
            with open(input_path, 'rb') as f:
                xml = etree.parse(f)

            with open(PRIVATE_KEY_PATH, 'rb') as f:
                key = f.read()
            with open(CERTIFICATE_PATH, 'rb') as f:
                cert = f.read()

            signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256", digest_algorithm="sha256")
            signed = signer.sign(xml, key=key, cert=cert)

            with open(output_path, 'wb') as f:
                f.write(etree.tostring(signed, pretty_print=True))

            return redirect(url_for('preview', filename=f"signed_{filename}"))
        except Exception as e:
            return f"Error signing file: {e}", 500

    return render_template('index.html')

@app.route('/preview/<filename>')
def preview(filename):
    path = os.path.join(app.config['SIGNED_FOLDER'], filename)
    if not os.path.exists(path):
        return "File not found", 404

    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    return render_template('preview.html', content=content, filename=filename)

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(app.config['SIGNED_FOLDER'], filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "File not found", 404

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000)
