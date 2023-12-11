# CRM Flask Application README

## Project Overview

This project is a Flask-based web application designed for user authentication, customer management, and secure data storage. It utilizes various encryption techniques, including Fernet and RSA, to ensure the confidentiality and integrity of sensitive information.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Testing](#testing)
6. [Folder Structure](#folder-structure)
7. [Technologies Used](#technologies-used)
8. [Contributing](#contributing)
9. [License](#license)

## Prerequisites

- Python (version 3.x)
- Pip (Python package installer)
- SQLite (or any other compatible database)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/your-repo.git
    ```

2. Navigate to the project directory:

    ```bash
    cd your-repo
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration

1. Create a `.env` file in the project root directory.

2. Add the following environment variables to the `.env` file:

    ```dotenv
    ENCRYPTION_KEY=your_secret_key_for_Fernet_encryption
    ```

    Replace `your_secret_key_for_Fernet_encryption` with a strong secret key for Fernet encryption.

## Usage

1. Run the application:

    ```bash
    python app.py
    ```

2. Access the application in a web browser at `http://localhost:5000`.

## Testing

To run tests, use the following command:

```bash
python -m unittest discover tests
```

## Folder Structure

```plaintext
your-repo/
│
├── app/
│   ├── static/
│   │   └── (static files: CSS, JS, etc.)
│   ├── templates/
│   │   └── (HTML templates)
│   ├── __init__.py
│   ├── app.py
│   ├── models.py
│   └── (other modules)
│
├── tests/
│   ├── __init__.py
│   ├── test_app.py
│   └── (other test modules)
│
├── .env
├── .gitignore
├── cert.pem
├── key.pem
├── private_key.pem
├── public_key.pem
├── README.md
├── requirements.txt
└── (other files and directories)
```

## Technologies Used

- Flask
- SQLAlchemy
- Flask-SQLAlchemy
- Bcrypt
- cryptography
- Flask-WTF
- Flask-Session
- Flask-Script
- Flask-Testing

## License

This project is licensed under the [MIT License](LICENSE).

---
