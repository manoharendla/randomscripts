import subprocess
import re

def get_crl_endpoints(cert_file):
    """
    Extracts CRL distribution point URLs from certificates in a PEM file.

    Args:
        cert_file (str): Path to the PEM file.

    Returns:
        list: A list of CRL distribution point URLs.
    """

    crl_urls = []
    try:
        with open(cert_file, 'r') as f:
            cert_data = ""
            in_cert = False
            for line in f:
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    cert_data = line
                elif "-----END CERTIFICATE-----" in line:
                    in_cert = False
                    cert_data += line
                    # Process the certificate
                    process = subprocess.Popen(
                        ["openssl", "x509", "-noout", "-text"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    stdout, stderr = process.communicate(input=cert_data)

                    if process.returncode == 0:
                        crl_match = re.search(r"CRL Distribution Points:\n([\s\S]*?)URI:(.*?)\n", stdout)
                        if crl_match:
                            urls = re.findall(r"URI:(.*?)\n", crl_match.group(1))
                            crl_urls.extend(url.strip() for url in urls)

                    cert_data = "" # reset cert data
                elif in_cert:
                    cert_data += line

    except FileNotFoundError:
        print(f"Error: File not found: {cert_file}")
    except subprocess.CalledProcessError as e:
        print(f"OpenSSL error: {e}")

    return crl_urls

if __name__ == "__main__":
    cert_file_path = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"  # Replace with your PEM file
    crl_endpoints = get_crl_endpoints(cert_file_path)

    if crl_endpoints:
        for url in crl_endpoints:
            print(url)
    else:
        print("No CRL distribution points found.")
