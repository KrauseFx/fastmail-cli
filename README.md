# fastmail-cli

Read-only Fastmail JMAP CLI focused on AI-agent friendly output.

## Setup

1. Copy `.env.example` to `.env` and set:
   - `FASTMAIL_READONLY_API_TOKEN`
   - `FASTMAIL_USERNAME` (optional, not used by the CLI)
2. Run the CLI:

```bash
python3 fastmail_cli.py list --pretty
```

## Commands

```bash
# List Inbox
python3 fastmail_cli.py list --limit 10

# Search (Inbox by default)
python3 fastmail_cli.py search "invoice" --from billing@example.com --limit 5

# Search all mailboxes
python3 fastmail_cli.py search "meeting notes" --all-mailboxes

# Read message (text)
python3 fastmail_cli.py read <email_id>

# Read message (full HTML)
python3 fastmail_cli.py read <email_id> --format html

# Read message (HTML stripped to text + links)
python3 fastmail_cli.py read <email_id> --format stripped

# Full thread view
python3 fastmail_cli.py thread <email_id>

# Export bodies to files
python3 fastmail_cli.py read <email_id> --out ./exports --save-formats text,html
python3 fastmail_cli.py thread <email_id> --out ./thread_exports --format stripped

# List/download attachments
python3 fastmail_cli.py attachments <email_id>
python3 fastmail_cli.py attachments <email_id> --download --out ./attachments
```

## Output formats

- JSON (default): structured output for automation.
- Text: pass `--output text` for human-friendly lines.

## Notes

- Uses the official Fastmail JMAP API session endpoint.
- Read-only by design. No mutation endpoints are called.
