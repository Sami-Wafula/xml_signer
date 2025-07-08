# verify_xml.py
from signxml import XMLVerifier
from lxml import etree
import argparse

def verify_signed_xml(xml_path, cert_path):
    try:
        with open(xml_path, 'rb') as f:
            signed_data = f.read()

        with open(cert_path, 'r') as f:
            cert = f.read()

        print("Verifying signature...")
        verified = XMLVerifier().verify(signed_data, x509_cert=cert)
        print("✅ Signature is valid!")

    except Exception as e:
        print("❌ Verification failed:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify signed XML using PEM certificate.")
    parser.add_argument("--xml", required=True, help="Path to signed XML file")
    parser.add_argument("--cert", required=True, help="Path to certificate in PEM format")

    args = parser.parse_args()
    verify_signed_xml(args.xml, args.cert)
