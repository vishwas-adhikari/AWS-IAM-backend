# AWS IAM Risk Analyzer (Backend)

Django REST API behind CloudLens. It collects IAM data from an AWS account with Boto3, evaluates each identity's effective permissions, finds privilege-escalation paths with NetworkX, and stores the results for the dashboard.

For the full project overview, risk model and limitations, see the [CloudLens-IAM README](https://github.com/vishwas-adhikari/CloudLens-IAM).

## Tech Stack
- **Framework:** Django 5+ and Django REST Framework
- **AWS Integration:** Boto3 (read-only calls covered by the AWS-managed `SecurityAudit` policy)
- **Analysis:** custom IAM policy evaluator, NetworkX for the identity graph and shortest paths
- **Database:** SQLite (`db.sqlite3`, plain file, not encrypted)

## Setup

Requires Python 3.11+.

1. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure the environment:**
   ```bash
   cp .env.example .env            # Windows: copy .env.example .env
   ```
   For local development set `DEBUG=True` and any `SECRET_KEY`. Other settings:

   | Variable | Default | Purpose |
   | :--- | :--- | :--- |
   | `DEBUG` | `False` | Django debug mode. |
   | `SECRET_KEY` | insecure dev key | Django secret key. |
   | `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hosts. |
   | `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated frontend origins. |
   | `LOG_LEVEL` | `INFO` | Backend log level. Scan errors are logged here, never returned to the client. |
   | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | unset | Optional. When both are set, a scan summary is sent to Telegram after each scan. |

3. **Create an AWS profile for scanning.** Use an identity that has only the AWS-managed `SecurityAudit` policy and add it to `~/.aws/credentials` (or `~/.aws/config` for SSO / `role_arn` profiles):
   ```bash
   aws configure --profile cloudlens-audit
   ```
   AWS keys are never put in `.env` or sent from the browser.

4. **Create the database and start the server:**
   ```bash
   python manage.py migrate
   python manage.py runserver      # http://localhost:8000
   ```

## API

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/profiles/` | Names of the AWS profiles configured on the server (no credentials). |
| `POST` | `/api/scan/` | Body `{"profile": "name"}`. Omit or leave empty to use the default credential chain. Runs a scan and returns the full report. |
| `GET` | `/api/history/` | All past scans, newest first. |
| `GET` | `/api/scan/<id>/` | One stored scan. |

Scan errors return clean messages only: `400` unknown profile, `401` invalid or expired credentials, `403` access denied, `500` anything else.

Each finding has a `rule_id` and `details`. For privilege-escalation findings, `details.hops` lists every step of the path (`from`, `to`, labels, `edge` and `techniques`).

## Project Layout

```text
core/                  Django app: models, serializers, API views, API tests
engine/
  aws_wrapper.py       AWS data collection (profiles, paginated IAM snapshot, managed policies,
                       credential report, MFA devices, account summary)
  policy_engine.py     Effective-permission evaluation (wildcards, NotAction/NotResource, Deny)
  graph_builder.py     Identity graph: users, roles, trust relationships
  privesc.py           Escalation edges and shortest paths to admin
  scanner.py           Runs a scan: findings, risk score, graph, notification
  risk_rules.py        Finding titles, severities and remediation text
  notifier.py          Optional Telegram summary
  tests/               Engine and scanner tests
```

## Tests

```bash
python manage.py test
```
The tests don't call AWS: responses are stubbed with botocore's `Stubber`, and profile tests use temporary AWS config files.
