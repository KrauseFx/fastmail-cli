# Fastmail CLI (skill)

## What this skill does
- Read-only access to Fastmail email via JMAP.
- List inbox, search mail, read a message, view a thread, list/download attachments.

## Installed tooling
- Repo files: `skills/fastmail-cli/fastmail_cli.py`
- Wrapper: `skills/fastmail-cli/run.sh`
- Env file: `skills/fastmail-cli/.env` (you create it)

## One-time setup
- Create `skills/fastmail-cli/.env` based on `skills/fastmail-cli/.env.example`.
- Set at least:
  - `FASTMAIL_READONLY_API_TOKEN` (Fastmail read-only API token)
  - `FASTMAIL_USERNAME` (optional)

## How you can ask
- "Show my latest 10 emails."
- "Search my email for 'invoice' from billing@… and show 5 results."
- "Read the email with id … and summarize it."
- "Show the whole thread for id …"
- "List attachments for id … and download them."

## CLI usage (optional)
- List inbox: `bash skills/fastmail-cli/run.sh list --limit 10 --pretty`
- Search: `bash skills/fastmail-cli/run.sh search "invoice" --limit 5 --pretty`
- Read: `bash skills/fastmail-cli/run.sh read <email_id> --format stripped --pretty`
- Thread: `bash skills/fastmail-cli/run.sh thread <email_id> --format stripped --pretty`
- Attachments: `bash skills/fastmail-cli/run.sh attachments <email_id> --pretty`

## Notes / limits
- Read-only by design.
- Always use `--all-mailboxes` flag for searches.
