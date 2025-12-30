# AWS IAM Risk Analyzer (Backend)

A lightweight, security-focused backend that scans AWS IAM environments for privilege escalation paths, dangerous misconfigurations, and excessive permissions.

## Tech Stack
- **Framework:** Django 5 + Django REST Framework
- **AWS Integration:** Boto3
- **Graph Analysis:** NetworkX (for Privilege Escalation detection)
- **Database:** SQLite (Dev) / PostgreSQL (Prod)

## Setup

1. **Create Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate