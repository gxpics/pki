""" 
This program creates a PQ PKI including a root CA and 2 intermediate CAs.
"""

from pathlib import Path
import subprocess
import shutil
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS

BASE_DIR = Path.home() / "pki" / "hybrid-pki"
root_dir = BASE_DIR /"rootCA"
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


def generate_root_config(root_dir, default_md=None):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"

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

{md_line}
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

def generate_intermediate_config(ca_dir, ca_name, default_md = None):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"
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

{md_line}
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


def generate_key(key_path, algorithm, options=None):
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = [
        "openssl",
        "genpkey",
        "-algorithm",
        algorithm
    ]

    if options:
        for option in options:
            command.extend([
                "-pkeyopt",
                option
            ])

    command.extend([
        "-out",
        str(key_path)
    ])

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
        csr_path,
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


    #generate_intermediate_config(intermediate1_dir, "intermediateCA1")
    #generate_intermediate_config(intermediate2_dir, "intermediateCA2")

    root_key = root_dir / "private" / "rootCA.key"
    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["root"]]

    #generate_key(root_key, root_policy["algorithm"], root_policy["options"])
    #generate_root_config(root_dir, root_policy["digest"])
    #create_root_certificate(root_dir)

    intermediate1_key = intermediate1_dir / "private" / "intermediateCA1.key"
    intermediate1_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["intermediate"]]
    #generate_key(intermediate1_key, intermediate1_policy["algorithm"], intermediate1_policy["options"])
    #generate_intermediate_config(intermediate1_dir, "intermediateCA1", intermediate1_policy["digest"]) 


    intermediate2_key = intermediate2_dir / "private" / "intermediateCA2.key"
    intermediate2_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["post_quantum"]["intermediate"]]  #ML-DSA65
    #generate_key(intermediate2_key, intermediate2_policy["algorithm"], intermediate2_policy["options"])
    #generate_intermediate_config(intermediate2_dir, "intermediateCA2", intermediate2_policy["digest"])

    #generate_intermediate_csr(intermediate1_dir, "intermediateCA1")
    #generate_intermediate_csr(intermediate2_dir, "intermediateCA2")

    #sign_intermediate(root_dir, intermediate1_dir, "intermediateCA1")
    #sign_intermediate(root_dir, intermediate2_dir, "intermediateCA2")
    verify_intermediate(root_dir, intermediate1_dir / "certs" / "intermediateCA1.crt") 
    verify_intermediate(root_dir, intermediate2_dir / "certs" / "intermediateCA2.crt")

if __name__ == "__main__":
    main()
