# sign_xml.py
import argparse
from signxml import XMLSigner, methods
from lxml import etree

def sign_xml(xml_path, key_path, cert_path, output_path):
    try:
        print("Reading input XML...")
        with open(xml_path, 'rb') as f:
            xml = etree.parse(f)

        print("Loading private key...")
        with open(key_path, 'rb') as f:
            key = f.read()

        print("Loading certificate...")
        with open(cert_path, 'rb') as f:
            cert = f.read()

        print("Signing...")
        signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256", digest_algorithm="sha256")
        signed = signer.sign(xml, key=key, cert=cert)

        print("Saving to file...")
        with open(output_path, 'wb') as f:
            f.write(etree.tostring(signed, pretty_print=True))

        print(f"✅ Signed XML written to: {output_path}")

    except Exception as e:
        print("❌ Error occurred:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign XML using a PEM private key and certificate.")
    parser.add_argument("--xml", required=True, help="Path to input XML file")
    parser.add_argument("--key", required=True, help="Path to private key in PEM format")
    parser.add_argument("--cert", required=True, help="Path to certificate in PEM format")
    parser.add_argument("--out", default="signed.xml", help="Output signed XML path")

    args = parser.parse_args()
    sign_xml(args.xml, args.key, args.cert, args.out)
