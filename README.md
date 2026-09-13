# PKI and Hybrid Post-Quantum PKI

This project builds a Public Key Infrastructure (PKI) from the ground up using OpenSSL and Python automation. It demonstrates certificate authority hierarchy, certificate issuance and verification, TLS socket programming, and deployment of PKI-issued certificates to a real Nginx HTTPS server.

The current implementation establishes a working PKI with a Root CA, two Intermediate CAs, and server certificates. The project will be extended to a hybrid post-quantum PKI incorporating post-quantum cryptographic algorithms such as ML-DSA.

## Project Goals

- Build a complete PKI using OpenSSL
- Automate PKI creation and certificate management with Python
- Create a Root CA and Intermediate CA hierarchy
- Generate and issue server certificates
- Construct and verify certificate chains
- Implement a Python TLS server for TLS experiments
- Deploy PKI-issued certificates to an Nginx HTTPS server
- Test TLS handshakes and certificate-chain verification
- Extend the PKI with post-quantum cryptography
- Explore migration from classical PKI to hybrid post-quantum PKI

## PKI Architecture

The current PKI uses the following certificate hierarchy:

```text
                     Root CA
                    /       \
                   /         \
      Intermediate CA 1    Intermediate CA 2
               |
               |
         Server Certificate
               |
        +------+------+
        |             |
        v             v
 Python TLS Server   Nginx Server
```

The Root CA acts as the trust anchor.

Intermediate CAs issue end-entity certificates so that the Root CA does not need to directly issue server certificates. This follows the hierarchical model commonly used in PKI deployments.

The generated server certificate can then be deployed to either the Python TLS server or Nginx.

## Repository Structure

```text
pki/
├── pq-pki/
│   ├── pq_pki_setup.py
│   ├── create_server.py
│   ├── start_server.py
│   ├── tls_server.py
│   ├── rootCA/
│   ├── intermediateCA1/
│   ├── intermediateCA2/
│   └── servers/
│
├── hybrid-pki/
│   ├── policy.py
│   ├── rootCA/
│   ├── intermediateCA1/
│   ├── intermediateCA2/
│   └── servers/
│
├── .gitignore
└── README.md

The directory structure will evolve as the hybrid post-quantum implementation is added.

## Python Automation

The PKI creation process is automated using Python. OpenSSL commands are executed from Python using the `subprocess` module.

The overall process is:

```text
Create CA directories
        |
        v
Initialize CA databases
        |
        v
Generate CA private keys
        |
        v
Generate Root CA certificate
        |
        v
Generate Intermediate CA CSRs
        |
        v
Sign Intermediate CA certificates
        |
        v
Generate server private key
        |
        v
Generate server CSR
        |
        v
Issue server certificate
        |
        v
Build certificate chain
        |
        v
Verify certificates
        |
        v
Deploy TLS server
```

The automation allows the PKI to be recreated consistently rather than manually executing each OpenSSL command.

## Python TLS Server

The project includes a Python TLS server for experimenting with TLS communication using certificates issued by the PKI.

The server uses Python socket programming together with TLS support to create an encrypted client-server connection.

Conceptually, the server performs:

```text
Create TCP socket
        |
        v
Bind to address and port
        |
        v
Configure TLS context
        |
        v
Load server certificate
and private key
        |
        v
Listen for connections
        |
        v
Accept TCP connection
        |
        v
Perform TLS handshake
        |
        v
Exchange encrypted data
```

The Python TLS server provides a simple environment for studying:

- TCP socket programming
- TLS context configuration
- Certificate loading
- TLS handshakes
- Certificate authentication
- Encrypted client-server communication

This complements the Nginx deployment by demonstrating how an application can use PKI certificates programmatically.

## Nginx TLS Deployment

The same PKI-issued server certificate can be deployed to an Nginx HTTPS server.

A typical Nginx TLS configuration is:

```nginx
server {
    listen 443 ssl;

    server_name localhost;

    ssl_certificate     /etc/nginx/server1-chain.crt;
    ssl_certificate_key /etc/nginx/server1.key;

    location / {
        return 200 "Hello from PKI TLS server\n";
    }
}
```

The server certificate chain contains the server certificate followed by the issuing Intermediate CA certificate:

```text
server1-chain.crt
|
+-- server1.crt
|
+-- intermediateCA1.crt
```

The Root CA certificate is normally not sent by the TLS server because the client is expected to have the Root CA installed or otherwise configured as a trust anchor.

## Enabling the Nginx Configuration

On Ubuntu, the Nginx site configuration can be stored under:

```text
/etc/nginx/sites-available/
```

and enabled using a symbolic link under:

```text
/etc/nginx/sites-enabled/
```

For example:

```bash
sudo ln -s \
    /etc/nginx/sites-available/myserver \
    /etc/nginx/sites-enabled/myserver
```

Test the Nginx configuration before starting or reloading the server:

```bash
sudo nginx -t
```

Start Nginx:

```bash
sudo systemctl start nginx
```

If Nginx is already running and the configuration has changed:

```bash
sudo systemctl reload nginx
```

Verify that Nginx is listening on HTTPS port 443:

```bash
sudo ss -tlnp | grep :443
```

## Testing the TLS Connection

OpenSSL can be used as a TLS client to connect to the Nginx server:

```bash
openssl s_client -connect localhost:443
```

A successful connection displays:

```text
CONNECTED
```

along with information about the TLS handshake, server certificate, certificate chain, protocol version, and negotiated cipher suite.

Because this project uses a private Root CA, the Root CA certificate can be explicitly supplied to the client:

```bash
openssl s_client \
    -connect localhost:443 \
    -CAfile /path/to/rootCA.crt
```

Successful certificate-chain verification should produce:

```text
Verify return code: 0 (ok)
```

The expected verification path is:

```text
Server Certificate
        |
        v
Intermediate CA
        |
        v
Root CA
        |
        v
Trusted by Client
```

Once the TLS connection is established, an HTTP request can be sent through the encrypted connection:

```text
GET / HTTP/1.1
Host: localhost

```

Nginx then returns an HTTP response through the TLS connection.

## Security

**Private keys must never be committed to this repository.**

The `.gitignore` file should exclude generated private keys and other sensitive PKI state.

For example:

```gitignore
# Private keys
*.key

# Python
__pycache__/
*.pyc

# OpenSSL CA database/state
index.txt
index.txt.*
serial
serial.old
*.srl
```

Before every commit, check:

```bash
git status
```

and verify that no Root CA, Intermediate CA, or server private keys are staged for commit.

## Technologies

- Python
- Python `socket` and `ssl` modules
- Python `subprocess`
- OpenSSL
- Nginx
- TLS / HTTPS
- X.509 certificates
- Public Key Infrastructure (PKI)
- Linux / Ubuntu
- Git / GitHub
- Post-Quantum Cryptography
- ML-DSA


## Project Status

**Completed phases:** Classical PKI and post-quantum PKI automation, including certificate generation, Python TLS server integration, and Nginx TLS deployment.

**Current phase:** Crypto-agile PKI automation. Cryptographic algorithms and parameters can be selected through a configurable policy, supporting algorithms such as RSA, ECDSA, and ML-DSA without changing the core PKI automation logic.

**Next phase:** Extend the crypto-agile PKI to a hybrid architecture that combines classical and post-quantum cryptographic mechanisms, followed by hybrid TLS integration and testing.
