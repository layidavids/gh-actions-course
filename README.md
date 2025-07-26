# cyph3r

This project was created to assist with the automation of key generation, key splitting and encryption with PGP.

It consists of the following modules:

- Key/Password/URL-Safe string generation module.
- Key Splitting and Reconstruction module that supports Shamir Secret Sharing (SSS) and XOR Operation.
- Data Encryption/Decryption Module using AES-GCM and AES-CBC.
- A module that combines all the operation performed above and encrypts the artefact using PGP.

## Usage (in the development environment only!)
The docker image built is not production ready 
- Docker is running the django dev and redis server
- Allowed hosts is set to any
- Django secret generated is stored as an env var

1. Install docker - https://docs.docker.com/

2. Build docker image

```bash
docker buildx build -t cyph3r:latest .
```

3. Run Image
```bash 
docker run -d -p 8080:8080 cyph3r:latest
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.