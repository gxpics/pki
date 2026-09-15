from pathlib import Path
import subprocess
import shutil
from pki_setup import  run_command, generate_key
# BASE_DIR, root_dir, intermediate1_dir, intermediate2_dir
from policy import SUPPORTED_ALGORITHMS, PKI_POLICY


BASE_DIR = None
root_dir = None

def create_server_dir(server1_dir):
    directories = [
        "certs",
        "csr",
        "private"
    ]

    for directory in directories:
        (server1_dir / directory).mkdir(
            parents=True,
            exist_ok=True
        )

def generate_server_csr(server_dir, server_name):
    command = [
        "openssl",
        "req",
        "-new",
        "-key",
        server_dir / "private" / f"{server_name}.key",
        "-out",
        server_dir / "csr" / f"{server_name}.csr",
        "-subj",
        f"/C=US/ST=New York/L=Rochester/O=Hybrid PKI Lab/CN={server_name}"
    ]

    run_command(command)

def sign_server(
    intermediate_dir,
    server_dir,
    server_name
):
    cert_path = server_dir / "certs" / f"{server_name}.crt"

    if cert_path.exists():
        print(f"Certificate already exists: {cert_path}")
        print("Skipping server certificate signing.")
        return

    command = [
        "openssl",
        "ca",
        "-batch",
        "-config",
        intermediate_dir / "openssl.cnf",
        "-extensions",
        "server_cert",
        "-days",
        "365",
        "-in",
        server_dir / "csr" / f"{server_name}.csr",
        "-out",
        cert_path
    ]

    run_command(command)


def verify_server(
    root_dir,
    intermediate_crt,
    server_dir,
    server_name
):
    """
    Verify the complete server cert chain
    """
    command = [
        "openssl",
        "verify",
        "-CAfile",
        root_dir / "certs" / "rootCA.crt",
        "-untrusted",
        intermediate_crt,
        server_dir / "certs" / f"{server_name}.crt"
    ]

    run_command(command)

def create_server_chain(
    server_dir,
    intermediate_dir,
    server_name,
    intermediate_name
):
    """
    server chain certificate = server certificate + intermediate certificate
    Python can concatenate them directly without calling cat
    """
    server_cert = (
        server_dir /
        "certs" /
        f"{server_name}.crt"
    )

    intermediate_cert = (
        intermediate_dir /
        "certs" /
        f"{intermediate_name}.crt"
    )

    chain_file = (
        server_dir /
        "certs" /
        f"{server_name}-chain.crt"
    )

    chain_file.write_text(
        server_cert.read_text()
        +
        intermediate_cert.read_text()
    )

    print(f"Created chain: {chain_file}")


def install_nginx_certificate(server_dir, server_name):
    """
    Copy the server chain certificate and key to nginx 
    """

    nginx_dir = Path("/etc/nginx/ssl")

    command = [
        "sudo",
        "mkdir",
        "-p",
        nginx_dir
    ]

    run_command(command)

    run_command([
        "sudo",
        "cp",
        server_dir / "certs" / f"{server_name}-chain.crt",
        nginx_dir / f"{server_name}-chain.crt"
    ])

    run_command([
        "sudo",
        "cp",
        server_dir / "private" / f"{server_name}.key",
        nginx_dir / f"{server_name}.key"
    ])


def generate_nginx_config(server_name):
    config = f"""
server {{
    listen 445 ssl;
    server_name localhost;

    ssl_certificate /etc/nginx/ssl/{server_name}-chain.crt;
    ssl_certificate_key /etc/nginx/ssl/{server_name}.key;

    location / {{
        return 200 "Post-Quantum PKI NGINX server\\n";
    }}
}}
"""

    config_path = Path(f"/tmp/{server_name}")

    config_path.write_text(config)

    run_command([
        "sudo",
        "cp",
        config_path,
        f"/etc/nginx/sites-available/{server_name}"
    ])


def enable_nginx_site(server_name):
    run_command([
        "sudo",
        "ln",
        "-s",
        f"/etc/nginx/sites-available/{server_name}",
        f"/etc/nginx/sites-enabled/{server_name}"
    ])

def test_nginx():
    run_command([
        "sudo",
        "nginx",
        "-t"
    ])

def reload_nginx():
    # Test nginx configuration first
    run_command([
        "sudo",
        "nginx",
        "-t"
    ])

    # Reload systemd service definitions if needed
    run_command([
        "sudo",
        "systemctl",
        "daemon-reload"
    ])

    # Determine whether nginx is running
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", "nginx"]
    )

    if result.returncode == 0:
        print("Nginx is active. Reloading nginx...")
        run_command([
            "sudo",
            "systemctl",
            "reload",
            "nginx"
        ])
    else:
        print("Nginx is inactive. Starting nginx...")
        run_command([
            "sudo",
            "systemctl",
            "start",
            "nginx"
        ])

def initialize_server(server_name, intermediate_dir, mode = "classical"):
    """
    mode = either "classical" or "post_quantum" depending on BASE_DIR
    """
    server_dir = BASE_DIR / "servers" / server_name
    server_key = server_dir / "private" / (server_name + ".key")
    
    if intermediate_dir.name == "intermediateCA1":
        intermediate_crt = intermediate_dir / "certs" / "intermediateCA1.crt"
    elif intermediate_dir.name == "intermediateCA2":
        intermediate_crt = intermediate_dir / "certs" / "intermediateCA2.crt"
    else:
        print(intermediate_dir.name + " is not a valid intermiedate directory")
        return

    create_server_dir(server_dir)

    server_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["server"]]
    generate_key(server_key, server_policy["algorithm"],server_policy["options"])

    generate_server_csr(server_dir, server_name)
    sign_server(intermediate_dir, server_dir, server_name)
    verify_server(root_dir, intermediate_crt, server_dir, server_name)


def main():
    global BASE_DIR, root_dir

    mode_choice  = input("Choose the mode (c for classical, p for post quantum): ")

    if mode_choice == "c":
        BASE_DIR = Path.home() / "pki" / "classical-pki"
        mode = "classical"
    else:
        BASE_DIR = Path.home() / "pki" / "pq-pki"
        mode = "post_quantum"

    root_dir = BASE_DIR /"rootCA"
    intermediate1_dir = BASE_DIR / "intermediateCA1"
    intermediate2_dir = BASE_DIR / "intermediateCA2"


    server_name = "server3"
    server_dir = BASE_DIR / "servers" / server_name
    server_key = server_dir / "private" / (server_name + ".key")
    intermediate_dir = intermediate2_dir


    initialize_server(server_name, intermediate_dir, mode)

    #create_server_chain(server_dir, intermediate_dir,server_name, intermediate_dir.name)
    #install_nginx_certificate(server_dir, server_name)
    #generate_nginx_config(server_name)
    #enable_nginx_site(server_name)
    #test_nginx()
    #reload_nginx()


if __name__ == "__main__":
    main()
