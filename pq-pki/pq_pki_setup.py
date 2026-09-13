""" 
This program creates a PQ PKI including a root CA and 2 intermediate CAs.
"""

from pathlib import Path
import subprocess
import shutil

BASE_DIR = Path.home() /"pki" / "pq-pki"
root_dir = BASE_DIR / "rootCA"
intermediate1_dir = BASE_DIR / "intermediateCA1"
intermediate2_dir = BASE_DIR / "intermediateCA2"


def run_command(command):
    try:
        print("\nRunning:")
        print(" ".join(str(x) for x in command))
        print()

        subprocess.run(
            [str(x) for x in command],
            check=True
        )

    except subprocess.CalledProcessError as e:
        print("Command failed.")
        print(e)
        raise

def create_ca_directories(ca_dir):
    directories = [
        "certs",
        "crl",
        "csr",
        "newcerts",
        "private"
    ]

    for directory in directories:
        path = ca_dir / directory
        path.mkdir(parents=True, exist_ok=True)

    print(f"Created CA directory structure: {ca_dir}")

def initialize_ca(ca_dir):
    index_file = ca_dir / "index.txt"
    serial_file = ca_dir / "serial"

    if not index_file.exists():
        index_file.touch()

    if not serial_file.exists():
        serial_file.write_text("1000\n")

    print(f"Initialized CA database: {ca_dir}")

def create_server_directories(server_dir):
    directories = [
        "certs",
        "csr",
        "private"
    ]

    for directory in directories:
        (server_dir / directory).mkdir(
            parents=True,
            exist_ok=True
        )

def generate_root_config(root_dir):
    config = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {root_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/rootCA.key
certificate       = $dir/certs/rootCA.crt

default_md        = default
default_days      = 3650
policy            = policy_loose
copy_extensions   = copy

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
prompt             = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C  = US
ST = New York
L  = Rochester
O  = PQ PKI Lab
OU = Root CA
CN = PQ Root CA

[ v3_root_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
"""

    config_path = root_dir / "openssl.cnf"
    config_path.write_text(config)

    print(f"Created {config_path}")

def generate_intermediate_config(ca_dir, ca_name):
    config = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {ca_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/{ca_name}.key
certificate       = $dir/certs/{ca_name}.crt

default_md        = default
default_days      = 1825
policy            = policy_loose
copy_extensions   = copy

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
prompt             = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C  = US
ST = New York
L  = Rochester
O  = PQ PKI Lab
OU = Intermediate CA
CN = {ca_name}

[ server_cert ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
"""

    config_path = ca_dir / "openssl.cnf"
    config_path.write_text(config)

    print(f"Created {config_path}")


def generate_mldsa_key(key_path):
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = [
        "openssl",
        "genpkey",
        "-algorithm",
        "ML-DSA-65",
        "-out",
        str(key_path)
    ]

    run_command(command)

def create_root_certificate(root_dir):
    """
    Create a self-signed certificate
    """
    command = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-key",
        root_dir / "private" / "rootCA.key",
        "-out",
        root_dir / "certs" / "rootCA.crt",
        "-config",
        root_dir / "openssl.cnf",
        "-extensions",
        "v3_root_ca",
        "-days",
        "3650"
    ]

    run_command(command)

def generate_intermediate_csr(ca_dir, ca_name):
    csr_path = ca_dir / "csr" / f"{ca_name}.csr"

    if csr_path.exists():
        print(f"CSR already exists: {csr_path}")
        print("Skipping CSR generation.")
        return

    command = [
        "openssl",
        "req",
        "-new",
        "-key",
        ca_dir / "private" / f"{ca_name}.key",
        "-out",
        ca_dir / "csr" / f"{ca_name}.csr",
        "-config",
        ca_dir / "openssl.cnf"
    ]

    run_command(command)

def sign_intermediate(root_dir, intermediate_dir, name):
    command = [
        "openssl",
        "ca",
        "-batch",
        "-config",
        root_dir / "openssl.cnf",
        "-extensions",
        "v3_intermediate_ca",
        "-days",
        "3650",
        "-in",
        intermediate_dir / "csr" / f"{name}.csr",
        "-out",
        intermediate_dir / "certs" / f"{name}.crt"
    ]

    run_command(command)

def verify_intermediate(root_dir, intermediate_cert):
    command = [
        "openssl",
        "verify",
        "-CAfile",
        root_dir / "certs" / "rootCA.crt",
        intermediate_cert
    ]

    run_command(command)

def main():

    #create_ca_directories(root_dir)
    #create_ca_directories(intermediate1_dir)
    #create_ca_directories(intermediate2_dir)

    #initialize_ca(root_dir)
    #initialize_ca(intermediate1_dir)
    #initialize_ca(intermediate2_dir)

    #create_server_directories(server1_dir)

    #generate_root_config(root_dir)
    #generate_intermediate_config(intermediate1_dir, "intermediateCA1")
    #generate_intermediate_config(intermediate2_dir, "intermediateCA2")

    root_key = root_dir / "private" / "rootCA.key"
    #generate_mldsa_key(root_key)

    #create_root_certificate(root_dir)

    #generate_mldsa_key(intermediate1_dir / "private" / "intermediateCA1.key")
    #generate_mldsa_key(intermediate2_dir / "private" / "intermediateCA2.key")
    
    #generate_intermediate_csr(intermediate1_dir, "intermediateCA1")
    #generate_intermediate_csr(intermediate2_dir, "intermediateCA2")

    #sign_intermediate(root_dir, intermediate1_dir, "intermediateCA1")
    #sign_intermediate(root_dir, intermediate2_dir, "intermediateCA2")
    verify_intermediate(root_dir, intermediate1_dir / "certs" / "intermediateCA1.crt") 
    verify_intermediate(root_dir, intermediate2_dir / "certs" / "intermediateCA2.crt")

if __name__ == "__main__":
    main()
