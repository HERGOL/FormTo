# FormTo

<p align="center">
  <img src="/logo.gif" alt="FormTo logo" />
</p>

**An open-source alternative to EmailJS — ultra-lightweight, easy to use, simple to integrate, and fully self-hostable.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org/)
[![Docker Pulls](https://img.shields.io/docker/pulls/yidirk/formto.svg)](https://hub.docker.com/r/yidirk/formto)

<p align="center">
  <a href="https://hub.docker.com/r/yidirk/formto">
    <img src="https://img.shields.io/badge/Docker%20Hub-yidirk%2Fformto-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="View on Docker Hub">
  </a>
</p>

---

## Overview

**FormTo** is a lightweight, self-hosted email sending service that exposes a simple REST API for sending emails from your applications. Unlike EmailJS and similar services, you maintain full control over your infrastructure, data, and SMTP credentials.

Every API key has its **recipient email fixed server-side, in the admin dashboard only** — client forms can never redirect where messages are delivered. Even if an API key leaks, it can never be used as an open relay to spam a third-party address.

---

## Features

### Core

- **Ultra-lightweight** — minimal dependencies, fast performance
- **Multi-tenant** — manage multiple projects with separate API keys
- **Fixed recipient per key** — the destination address is set once in the admin dashboard; the client-side form can never choose or override it (anti open-relay by design)
- **Newsletter subscriptions** — a dedicated `/api/subscribe` endpoint, a subscribers table per project (view / export as CSV / delete), and a ready-to-embed HTML sign-up widget with a live in-dashboard editor and preview
- **Real-time dashboard** — monitor email delivery stats and logs
- **Multi-language UI** — built-in i18n (FR/EN/ES/DE) with automatic browser language detection
- **Easy integration** — simple REST API, works with any programming language
- **Domain whitelisting** — control which domains can be used as sender
- **Origin restriction** — lock an API key to specific website origins for safe browser-side use
- **Per-key and global rate limiting** — sliding-window limits with live usage stats
- **Analytics** — track success rates, hourly/daily stats, and per-tenant activity
- **Modern UI** — dark theme dashboard built with Tailwind CSS and Alpine.js

### Security

- Recipient address never accepted from the client — fixed server-side per API key
- Brute-force protection on the admin login (auto-lockout after repeated failed attempts)
- Constant-time password comparison, CRLF header-injection sanitization, request body size cap
- Security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`)
- SMTP test sends a real HTML+text email so you can confirm delivery end-to-end, not just a connection check

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
      - "3080:3000"
    environment:
      - PORT=3080
      - RACK_ENV=production
      - ADMIN_PASSWORD=wMlM4w1S&CYjZ*q
      - RATE_LIMIT_GLOBAL_MAX=1000
      - RATE_LIMIT_GLOBAL_WINDOW=3600
      - ADMIN_LOGIN_MAX_FAILS=10
      - ADMIN_LOGIN_FAIL_WINDOW=300
    volumes:
      - ./data:/app/data
```

### Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Application port (default: `3000`) |
| `RACK_ENV` | Environment mode (`production`) |
| `ADMIN_PASSWORD` | Admin dashboard password |
| `RATE_LIMIT_GLOBAL_MAX` | Max requests across all keys per window (default: `1000`) |
| `RATE_LIMIT_GLOBAL_WINDOW` | Global rate limit window in seconds (default: `3600`) |
| `ADMIN_LOGIN_MAX_FAILS` | Failed admin login attempts before a temporary lockout (default: `10`) |
| `ADMIN_LOGIN_FAIL_WINDOW` | Lockout window in seconds for admin login attempts (default: `300`) |

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
- **Recipient email** — where messages sent through this key will land (fixed here, never sent by the client)

Click **Create Key**.

### 3. (Optional) Enable Newsletter Sign-ups

Go to the **Newsletter** tab, pick your project, and copy the ready-made HTML widget (already wired to your API key and instance URL) onto your site. Subscribers show up live in the same tab, with CSV export.

### 4. Start Sending Emails

Open the **API Documentation** tab and check the integration examples.