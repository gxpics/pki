# Hybrid PKI

This project implements a **hybrid Public Key Infrastructure (PKI)** that combines classical and post-quantum cryptography.

The hybrid PKI currently uses a **dual-certificate approach**. Each CA and server has separate classical and post-quantum keys and certificates.

## Architecture

The project contains two PKI hierarchies:

```text
hybrid-pki/
├── classical-pki/
│   ├── rootCA/
│   ├── intermediateCA1/
│   ├── intermediateCA2/
│   └── servers/
│
└── pq-pki/
    ├── rootCA/
    ├── intermediateCA1/
    ├── intermediateCA2/
    └── servers/
```

Each logical entity therefore has two cryptographic identities:

- A **classical key and certificate**
- A **post-quantum key and certificate**

For example, a server has:

```text
Server
├── Classical private key
├── Classical certificate
├── Post-quantum private key
└── Post-quantum certificate
```

The certificate chains are maintained independently:

```text
Classical PKI:
Root CA
   ↓
Intermediate CA
   ↓
Server Certificate

Post-Quantum PKI:
Root CA
   ↓
Intermediate CA
   ↓
Server Certificate
```

Together, these two certificate chains provide the basis for hybrid authentication.

## Crypto Agility

The PKI is designed to support configurable cryptographic algorithms. Classical and post-quantum algorithms can be selected through the PKI policy rather than being hard-coded into the certificate-generation functions.

Supported algorithms may include:

- RSA
- ECDSA
- ML-DSA

## Current Status

Implemented:

- Classical PKI
- Post-quantum PKI
- Root and intermediate CAs
- Server certificate generation
- Automated key and certificate generation
- Dual classical/PQ certificates for CAs and servers
- Certificate-chain verification
- Crypto-agile algorithm selection

## Future Work

A **composite certificate** approach has not yet been implemented.
