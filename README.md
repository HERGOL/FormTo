# FormTo

<p align="center">
  <img src="/logo.gif" alt="FormTo logo" />
</p>

**An open-source alternative to EmailJS — ultra-lightweight, easy to use, simple to integrate, and fully self-hostable.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org/)

---

## Overview

**FormTo** is a lightweight, self-hosted email sending service that exposes a simple REST API for sending emails from your applications. Unlike EmailJS and similar services, you maintain full control over your infrastructure, data, and SMTP credentials.

---

## Features

### Core

- **Ultra-lightweight** — minimal dependencies, fast performance
- **Multi-tenant** — manage multiple projects with separate API keys
- **Real-time dashboard** — monitor email delivery stats and logs
- **Multi-language UI** — built-in i18n with automatic browser language detection
- **Easy integration** — simple REST API, works with any programming language
- **Domain whitelisting** — control which domains can be used as sender
- **Analytics** — track success rates, hourly/daily stats, and per-tenant activity
- **Modern UI** — dark theme dashboard built with Tailwind CSS and Alpine.js

### Technical

- Zero external dependencies (except frontend libraries)
- RESTful API with JSON responses
- Bearer token authentication
- Automatic browser language detection
- LocalStorage persistence for user preferences
- Responsive design (mobile-friendly)
- Chart.js integration for data visualization

---

## Run with Docker Compose

### 1. Clone the project

```bash
git clone https://github.com/your-username/formto.git
cd formto
```

### 2. Start the application

```bash
docker compose up -d
```

### 3. Access the app

```
http://localhost:3000
```

---

## Docker Compose Configuration

```yaml
        services:
          formto:
            image: yidirk/formto:latest
            container_name: formto
            restart: unless-stopped
            ports:
              - "3000:3000"
            environment:
              - PORT=3000
              - RACK_ENV=production
              - ADMIN_PASSWORD=wMlM4w1S&CYjZ*q
            volumes:
              - ./data:/app/data
            healthcheck:
              test: [ "CMD", "curl", "-f", "http://localhost:3000" ]
              interval: 30s
              timeout: 5s
              retries: 3
```

### Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Application port (default: `3000`) |
| `RACK_ENV` | Environment mode (`production`) |
| `ADMIN_PASSWORD` | Admin dashboard password |

---

## First-Time Setup

### 1. Access the Dashboard

Open your browser and navigate to:

```
http://your-ip:3000
```

Enter your admin password (set via the environment variable or the first-time setup screen).

### 2. Create Your First SMTP Configuration

Go to the **Configuration** tab and fill in your SMTP details:

- Project name (e.g., `My Website`)
- SMTP host (e.g., `smtp.gmail.com`)
- SMTP port (e.g., `587`)
- SMTP username and password
- Sender email and display name

Click **Create Key**.

### 3. Start Sending Emails

Open the **API Documentation** tab and check the integration examples.