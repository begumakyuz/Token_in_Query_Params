# Contributing to Token in Query Params

Thank you for your interest in contributing to this security project! We follow professional standards to ensure the codebase remains clean, secure, and well-documented.

## Code of Conduct

Help us keep the community healthy and inclusive. Please treat everyone with respect and follow our professional guidelines.

## How to Contribute

### 1. Reporting Security Issues
If you find a security vulnerability, please do NOT open a public issue. Email the project maintainer directly or use the GitHub Security Advisory tool.

### 2. Suggesting Enhancements
Use GitHub Issues to suggest new features or improvements. Provide as much detail as possible about the use case and reasoning.

### 3. Pull Requests
1. Fork the repository.
2. Create a new branch for your feature or bugfix (`git checkout -b feature-my-improvement`).
3. Follow the **Style Guide**:
    - Python: PEP 8 compliant.
    - Rust: `cargo fmt` and `cargo clippy` passed.
    - Markdown: Follow standard GFM syntax.
4. Add unit tests for any new functionality.
5. Ensure all CI/CD checks pass.
6. Submit a Pull Request with a clear description of the change.

## Project Structure

- `app.py`: Main Flask application.
- `core/`: Core security logic and middleware.
- `forensics/`: Incident logs and forensic analysis results.
- `nginx/`: Reverse proxy configuration and log scrubbing rules.
- `tools/`: Security utilities and automated forensic engines.
- `tests/`: Automated security audit and integration tests.

## Local Development

1. Install dependencies: `pip install -r requirements.txt`.
2. Build Docker environment: `docker-compose up -d --build`.
3. Run tests: `pytest tests/`.

Thank you for helping us build a more secure web!
