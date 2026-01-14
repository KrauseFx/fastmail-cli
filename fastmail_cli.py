#!/usr/bin/env python3
import argparse
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


DEFAULT_SESSION_URL = "https://api.fastmail.com/jmap/session"
JMAP_CAPABILITIES = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]
BASE_EMAIL_PROPERTIES = [
    "id",
    "threadId",
    "subject",
    "from",
    "to",
    "cc",
    "bcc",
    "receivedAt",
    "sentAt",
    "preview",
    "hasAttachment",
    "size",
    "mailboxIds",
    "keywords",
]
BODY_PROPERTIES = ["textBody", "htmlBody", "bodyValues", "bodyStructure"]


def load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if value and value[0] in ("'", '"') and value[-1] == value[0]:
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value


def http_json(method, url, token, payload=None):
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"br", "p", "div", "li"}:
            self.text_parts.append("\n")
        if tag == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value)

    def handle_data(self, data):
        if data:
            self.text_parts.append(data)

    def get_text(self):
        text = " ".join(self.text_parts)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)


def sanitize_filename(name, default="file", max_len=120):
    if not name:
        name = default
    safe = []
    for ch in name:
        if ord(ch) < 128 and (ch.isalnum() or ch in ("-", "_", ".", " ")):
            safe.append(ch)
        else:
            safe.append("_")
    cleaned = "".join(safe).strip().replace(" ", "_")
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    if not cleaned:
        cleaned = default
    return cleaned[:max_len]


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def unique_path(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    counter = 1
    while True:
        candidate = f"{base}-{counter}{ext}"
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def build_email_filename(email_obj, suffix):
    subject = sanitize_filename(email_obj.get("subject") or "message")
    received = email_obj.get("receivedAt") or email_obj.get("sentAt") or ""
    received = received.replace(":", "-")
    email_id = email_obj.get("id") or "unknown"
    base = f"{received}_{subject}_{email_id}".strip("_")
    return sanitize_filename(f"{base}.{suffix}", default=f"message.{suffix}", max_len=180)


class JMAPClient:
    def __init__(self, token, session_url=DEFAULT_SESSION_URL):
        self.token = token
        self.session_url = session_url
        self._session = None
        self._account_id = None

    def session(self):
        if self._session is None:
            self._session = http_json("GET", self.session_url, self.token)
            self._account_id = self._session.get("primaryAccounts", {}).get(
                "urn:ietf:params:jmap:mail"
            )
            if not self._account_id:
                accounts = self._session.get("accounts", {})
                if accounts:
                    self._account_id = next(iter(accounts.keys()))
        return self._session

    @property
    def account_id(self):
        if self._account_id is None:
            self.session()
        return self._account_id

    @property
    def api_url(self):
        return self.session().get("apiUrl")

    @property
    def download_url(self):
        return self.session().get("downloadUrl")

    def call(self, method_calls):
        payload = {"using": JMAP_CAPABILITIES, "methodCalls": method_calls}
        return http_json("POST", self.api_url, self.token, payload)

    def require_account(self):
        if not self.account_id:
            raise RuntimeError("Unable to determine JMAP mail account id.")


def extract_method_response(responses, tag):
    for method, data, response_tag in responses:
        if response_tag != tag:
            continue
        if method == "error":
            raise RuntimeError(f"JMAP error: {json.dumps(data)}")
        return method, data
    raise RuntimeError(f"Missing JMAP response for tag {tag}")


def list_inbox(client, limit=20, position=0):
    client.require_account()
    mailbox_resp = client.call(
        [["Mailbox/query", {"accountId": client.account_id, "filter": {"role": "inbox"}, "limit": 1}, "mb"]]
    )
    _, mailbox_data = extract_method_response(mailbox_resp["methodResponses"], "mb")
    inbox_ids = mailbox_data.get("ids", [])
    if not inbox_ids:
        raise RuntimeError("Inbox mailbox not found.")
    inbox_id = inbox_ids[0]

    query_resp = client.call(
        [
            [
                "Email/query",
                {
                    "accountId": client.account_id,
                    "filter": {"inMailbox": inbox_id},
                    "sort": [{"property": "receivedAt", "isAscending": False}],
                    "position": position,
                    "limit": limit,
                },
                "q",
            ]
        ]
    )
    _, query_data = extract_method_response(query_resp["methodResponses"], "q")
    ids = query_data.get("ids", [])
    if not ids:
        return {"mailboxId": inbox_id, "total": query_data.get("total", 0), "list": []}

    get_resp = client.call(
        [
            [
                "Email/get",
                {
                    "accountId": client.account_id,
                    "ids": ids,
                    "properties": BASE_EMAIL_PROPERTIES,
                },
                "g",
            ]
        ]
    )
    _, get_data = extract_method_response(get_resp["methodResponses"], "g")
    return {"mailboxId": inbox_id, "total": query_data.get("total", 0), "list": get_data.get("list", [])}


def find_mailbox_by_name(client, name):
    """Find a mailbox by name (case-insensitive)."""
    mailbox_resp = client.call(
        [["Mailbox/get", {"accountId": client.account_id}, "mb"]]
    )
    _, mailbox_data = extract_method_response(mailbox_resp["methodResponses"], "mb")
    mailboxes = mailbox_data.get("list", [])
    
    name_lower = name.lower()
    for mb in mailboxes:
        if mb.get("name", "").lower() == name_lower:
            return mb["id"]
    
    raise RuntimeError(f"Mailbox/label '{name}' not found. Available: {', '.join([m.get('name', '') for m in mailboxes])}")


def build_search_filter(args, inbox_id, label_id=None):
    filter_obj = {}
    if args.query:
        filter_obj["text"] = args.query
    if args.text:
        filter_obj["text"] = args.text
    if args.subject:
        filter_obj["subject"] = args.subject
    if args.from_addr:
        filter_obj["from"] = args.from_addr
    if args.to_addr:
        filter_obj["to"] = args.to_addr
    if args.cc:
        filter_obj["cc"] = args.cc
    if args.bcc:
        filter_obj["bcc"] = args.bcc
    if args.before:
        filter_obj["before"] = args.before
    if args.after:
        filter_obj["after"] = args.after
    
    # Priority: --label > default inbox (if not --all-mailboxes)
    if label_id:
        filter_obj["inMailbox"] = label_id
    elif not args.all_mailboxes:
        filter_obj["inMailbox"] = inbox_id
    return filter_obj


def search_mail(client, args):
    client.require_account()
    inbox_id = None
    label_id = None
    
    # If --label is specified, find that mailbox
    if hasattr(args, 'label') and args.label:
        label_id = find_mailbox_by_name(client, args.label)
    elif not args.all_mailboxes:
        # Default to inbox if not searching all mailboxes
        mailbox_resp = client.call(
            [["Mailbox/query", {"accountId": client.account_id, "filter": {"role": "inbox"}, "limit": 1}, "mb"]]
        )
        _, mailbox_data = extract_method_response(mailbox_resp["methodResponses"], "mb")
        inbox_ids = mailbox_data.get("ids", [])
        if not inbox_ids:
            raise RuntimeError("Inbox mailbox not found.")
        inbox_id = inbox_ids[0]

    filter_obj = build_search_filter(args, inbox_id, label_id)
    query_resp = client.call(
        [
            [
                "Email/query",
                {
                    "accountId": client.account_id,
                    "filter": filter_obj,
                    "sort": [{"property": "receivedAt", "isAscending": False}],
                    "position": args.position,
                    "limit": args.limit,
                },
                "q",
            ]
        ]
    )
    _, query_data = extract_method_response(query_resp["methodResponses"], "q")
    ids = query_data.get("ids", [])
    if not ids:
        return {"mailboxId": inbox_id, "total": query_data.get("total", 0), "list": []}

    get_resp = client.call(
        [
            [
                "Email/get",
                {
                    "accountId": client.account_id,
                    "ids": ids,
                    "properties": BASE_EMAIL_PROPERTIES,
                },
                "g",
            ]
        ]
    )
    _, get_data = extract_method_response(get_resp["methodResponses"], "g")
    return {"mailboxId": inbox_id, "total": query_data.get("total", 0), "list": get_data.get("list", [])}


def resolve_thread_id(client, identifier, id_type):
    if id_type == "thread":
        return identifier
    items = get_emails(client, [identifier], include_bodies=False)
    if not items:
        raise RuntimeError(f"Email not found: {identifier}")
    thread_id = items[0].get("threadId")
    if not thread_id:
        raise RuntimeError(f"Thread id missing for email: {identifier}")
    return thread_id


def fetch_thread_emails(client, thread_id, include_bodies=False, max_body_bytes=0, include_body_structure=False):
    client.require_account()
    query_resp = client.call(
        [
            [
                "Email/query",
                {
                    "accountId": client.account_id,
                    "filter": {"inThread": thread_id},
                    "sort": [{"property": "receivedAt", "isAscending": True}],
                },
                "q",
            ]
        ]
    )
    _, query_data = extract_method_response(query_resp["methodResponses"], "q")
    ids = query_data.get("ids", [])
    if not ids:
        return []
    extra_props = ["bodyStructure"] if include_body_structure else None
    return get_emails(
        client,
        ids,
        include_bodies=include_bodies,
        extra_props=extra_props,
        max_body_bytes=max_body_bytes,
    )


def extract_body(email_obj, prefer="text"):
    body_values = email_obj.get("bodyValues", {}) or {}
    if prefer == "text":
        parts = email_obj.get("textBody") or []
    else:
        parts = email_obj.get("htmlBody") or []
    values = []
    for part in parts:
        part_id = part.get("partId")
        if not part_id:
            continue
        value = body_values.get(part_id, {}).get("value")
        if value:
            values.append(value)
    return "\n".join(values).strip()


def extract_text_and_links(html):
    parser = HTMLTextExtractor()
    parser.feed(html)
    return parser.get_text(), parser.links


def get_emails(client, ids, include_bodies=False, extra_props=None, max_body_bytes=0):
    client.require_account()
    properties = list(BASE_EMAIL_PROPERTIES)
    if extra_props:
        for prop in extra_props:
            if prop not in properties:
                properties.append(prop)
    if include_bodies:
        for prop in BODY_PROPERTIES:
            if prop not in properties:
                properties.append(prop)
    args = {"accountId": client.account_id, "ids": ids, "properties": properties}
    if include_bodies:
        args["fetchTextBodyValues"] = True
        args["fetchHTMLBodyValues"] = True
        if max_body_bytes and max_body_bytes > 0:
            args["maxBodyValueBytes"] = max_body_bytes
    get_resp = client.call(
        [
            [
                "Email/get",
                args,
                "g",
            ]
        ]
    )
    _, get_data = extract_method_response(get_resp["methodResponses"], "g")
    items = get_data.get("list", [])
    return items


def read_email(client, email_id, max_body_bytes=0):
    items = get_emails(client, [email_id], include_bodies=True, max_body_bytes=max_body_bytes)
    if not items:
        raise RuntimeError(f"Email not found: {email_id}")
    return items[0]


def collect_attachments(body_structure, include_inline=False):
    attachments = []

    def walk(part):
        if not part:
            return
        for sub in part.get("subParts", []) or []:
            walk(sub)
        blob_id = part.get("blobId")
        if not blob_id:
            return
        disposition = (part.get("disposition") or "").lower()
        name = part.get("name") or ""
        mime_type = part.get("type") or ""
        is_attachment = disposition == "attachment"
        is_inline = disposition == "inline"
        is_named_binary = bool(name) and mime_type and not mime_type.startswith("text/")
        if not (is_attachment or (include_inline and is_inline) or is_named_binary):
            return
        attachments.append(
            {
                "partId": part.get("partId"),
                "blobId": blob_id,
                "name": name,
                "type": mime_type,
                "size": part.get("size"),
                "disposition": disposition,
                "cid": part.get("cid"),
            }
        )

    walk(body_structure or {})
    return attachments


def attachment_filename(attachment, fallback):
    name = attachment.get("name") or fallback
    if "." not in name:
        ext = mimetypes.guess_extension((attachment.get("type") or "").split(";")[0].strip())
        if ext:
            name = f"{name}{ext}"
    return sanitize_filename(name, default=fallback, max_len=140)


def download_attachment(client, attachment, out_dir, prefix=""):
    ensure_dir(out_dir)
    name = attachment_filename(attachment, fallback="attachment")
    url_name = attachment.get("name") or name
    if prefix:
        name = sanitize_filename(f"{prefix}_{name}", default=name, max_len=180)
    path = unique_path(os.path.join(out_dir, name))
    download_url = client.download_url
    if not download_url:
        raise RuntimeError("JMAP downloadUrl missing from session.")
    mime_type = attachment.get("type") or "application/octet-stream"
    url = download_url.format(
        accountId=client.account_id,
        blobId=attachment.get("blobId"),
        name=urllib.parse.quote(url_name),
        type=urllib.parse.quote(mime_type),
    )
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {client.token}"})
    with urllib.request.urlopen(request) as response:
        data = response.read()
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def save_email_bodies(email_obj, out_dir, formats):
    ensure_dir(out_dir)
    saved = []
    email_id = email_obj.get("id")
    for fmt in formats:
        fmt = fmt.lower()
        if fmt == "text":
            content = extract_body(email_obj, prefer="text")
            if not content:
                html = extract_body(email_obj, prefer="html")
                content, _ = extract_text_and_links(html)
            suffix = "txt"
        elif fmt == "html":
            content = extract_body(email_obj, prefer="html")
            suffix = "html"
        elif fmt == "stripped":
            html = extract_body(email_obj, prefer="html")
            content, _ = extract_text_and_links(html)
            if not content:
                content = extract_body(email_obj, prefer="text")
            suffix = "txt"
        else:
            continue
        filename = build_email_filename(email_obj, suffix)
        path = unique_path(os.path.join(out_dir, filename))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content or "")
        saved.append({"emailId": email_id, "format": fmt, "path": path})
    return saved


def attachments_dir_for_email(base_out, email_obj):
    email_id = sanitize_filename(email_obj.get("id") or "email")
    return os.path.join(base_out, email_id)


def format_addresses(addresses):
    if not addresses:
        return ""
    parts = []
    for addr in addresses:
        name = addr.get("name") or ""
        email = addr.get("email") or ""
        if name and email:
            parts.append(f"{name} <{email}>")
        elif email:
            parts.append(email)
        elif name:
            parts.append(name)
    return ", ".join(parts)


def output_json(data, pretty=False):
    if pretty:
        print(json.dumps(data, indent=2, ensure_ascii=True))
    else:
        print(json.dumps(data, ensure_ascii=True))


def output_list_text(result):
    for item in result.get("list", []):
        received = item.get("receivedAt", "")
        sender = format_addresses(item.get("from"))
        subject = item.get("subject") or ""
        preview = item.get("preview") or ""
        print(f"{item.get('id')} | {received} | {sender} | {subject}")
        if preview:
            print(f"  {preview}")


def output_read_text(email_obj, mode):
    subject = email_obj.get("subject") or ""
    sender = format_addresses(email_obj.get("from"))
    to = format_addresses(email_obj.get("to"))
    received = email_obj.get("receivedAt") or ""
    print(f"Subject: {subject}")
    if sender:
        print(f"From: {sender}")
    if to:
        print(f"To: {to}")
    if received:
        print(f"Received: {received}")
    print("")
    if mode == "html":
        html = extract_body(email_obj, prefer="html")
        print(html)
        return
    if mode == "text":
        text = extract_body(email_obj, prefer="text")
        if not text:
            html = extract_body(email_obj, prefer="html")
            text, _ = extract_text_and_links(html)
        print(text)
        return
    if mode == "stripped":
        html = extract_body(email_obj, prefer="html")
        text, links = extract_text_and_links(html)
        if not text:
            text = extract_body(email_obj, prefer="text")
        print(text)
        if links:
            print("\nLinks:")
            for link in links:
                print(f"- {link}")


def output_thread_text(emails, mode):
    for idx, email_obj in enumerate(emails, start=1):
        if idx > 1:
            print("\n" + ("-" * 40) + "\n")
        output_read_text(email_obj, mode)


def output_attachments_text(attachments, downloaded=None):
    for attachment in attachments:
        name = attachment.get("name") or ""
        mime_type = attachment.get("type") or ""
        size = attachment.get("size") or ""
        disp = attachment.get("disposition") or ""
        print(f"{name} | {mime_type} | {size} | {disp} | {attachment.get('blobId')}")
    if downloaded:
        print("\nDownloaded:")
        for item in downloaded:
            print(f"{item.get('name')} -> {item.get('path')}")


def parse_formats(value):
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="fastmail",
        description="Fastmail JMAP CLI (read-only).",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--session-url",
        default=os.environ.get("FASTMAIL_SESSION_URL", DEFAULT_SESSION_URL),
        help="Override JMAP session URL.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List Inbox emails.")
    list_parser.add_argument("--limit", type=int, default=20, help="Max results.")
    list_parser.add_argument("--position", type=int, default=0, help="Offset position.")

    search_parser = subparsers.add_parser("search", help="Search emails.")
    search_parser.add_argument("query", nargs="?", default="", help="Text search query.")
    search_parser.add_argument("--text", help="Search full text.")
    search_parser.add_argument("--subject", help="Search subject.")
    search_parser.add_argument("--from", dest="from_addr", help="Search from address.")
    search_parser.add_argument("--to", dest="to_addr", help="Search to address.")
    search_parser.add_argument("--cc", help="Search cc address.")
    search_parser.add_argument("--bcc", help="Search bcc address.")
    search_parser.add_argument("--before", help="Before date/time (RFC3339).")
    search_parser.add_argument("--after", help="After date/time (RFC3339).")
    search_parser.add_argument("--limit", type=int, default=20, help="Max results.")
    search_parser.add_argument("--position", type=int, default=0, help="Offset position.")
    search_parser.add_argument(
        "--all-mailboxes",
        action="store_true",
        help="Search all mailboxes (default: Inbox only).",
    )
    search_parser.add_argument(
        "--label",
        help="Search in specific mailbox/label by name (e.g., 'Travel').",
    )

    read_parser = subparsers.add_parser("read", help="Read a single email by id.")
    read_parser.add_argument("email_id", help="Email id.")
    read_parser.add_argument(
        "--format",
        choices=["text", "html", "stripped", "json"],
        default="text",
        help="Body format (default: text).",
    )
    read_parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=0,
        help="Truncate body values to this size in bytes (0 = no limit).",
    )
    read_parser.add_argument(
        "--out",
        help="Write message body to directory (sanitized filenames).",
    )
    read_parser.add_argument(
        "--save-formats",
        help="Comma-separated formats to save (text,html,stripped).",
    )
    read_parser.add_argument(
        "--download-attachments",
        action="store_true",
        help="Download attachments for this email.",
    )
    read_parser.add_argument(
        "--attachments-out",
        help="Directory for downloaded attachments.",
    )
    read_parser.add_argument(
        "--include-inline",
        action="store_true",
        help="Include inline parts as attachments.",
    )

    thread_parser = subparsers.add_parser("thread", help="Show full thread.")
    thread_parser.add_argument("id", help="Email id or thread id.")
    thread_parser.add_argument(
        "--id-type",
        choices=["email", "thread"],
        default="email",
        help="Interpret id as email or thread id (default: email).",
    )
    thread_parser.add_argument(
        "--format",
        choices=["text", "html", "stripped", "json"],
        default="text",
        help="Body format (default: text).",
    )
    thread_parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=0,
        help="Truncate body values to this size in bytes (0 = no limit).",
    )
    thread_parser.add_argument(
        "--out",
        help="Write message bodies to directory (sanitized filenames).",
    )
    thread_parser.add_argument(
        "--save-formats",
        help="Comma-separated formats to save (text,html,stripped).",
    )
    thread_parser.add_argument(
        "--download-attachments",
        action="store_true",
        help="Download attachments for all messages in thread.",
    )
    thread_parser.add_argument(
        "--attachments-out",
        help="Directory for downloaded attachments.",
    )
    thread_parser.add_argument(
        "--include-inline",
        action="store_true",
        help="Include inline parts as attachments.",
    )

    attach_parser = subparsers.add_parser("attachments", help="List/download attachments.")
    attach_parser.add_argument("email_id", help="Email id.")
    attach_parser.add_argument(
        "--download",
        action="store_true",
        help="Download attachments.",
    )
    attach_parser.add_argument(
        "--out",
        help="Directory for downloaded attachments.",
    )
    attach_parser.add_argument(
        "--include-inline",
        action="store_true",
        help="Include inline parts as attachments.",
    )

    return parser


def main():
    load_env()
    parser = build_parser()
    args = parser.parse_args()

    token = os.environ.get("FASTMAIL_READONLY_API_TOKEN")
    if not token:
        print("Missing FASTMAIL_READONLY_API_TOKEN in environment.", file=sys.stderr)
        return 2

    client = JMAPClient(token=token, session_url=args.session_url)

    if args.command == "list":
        result = list_inbox(client, limit=args.limit, position=args.position)
        if args.output == "json":
            output_json(result, pretty=args.pretty)
        else:
            output_list_text(result)
        return 0

    if args.command == "search":
        result = search_mail(client, args)
        if args.output == "json":
            output_json(result, pretty=args.pretty)
        else:
            output_list_text(result)
        return 0

    if args.command == "read":
        email_obj = read_email(client, args.email_id, max_body_bytes=args.max_body_bytes)
        saved = []
        downloaded = []
        attachments = []
        formats = parse_formats(args.save_formats)
        if args.out or formats:
            formats = formats or ([args.format] if args.format in {"text", "html", "stripped"} else ["text"])
            saved = save_email_bodies(email_obj, args.out or ".", formats)
        if args.download_attachments:
            attachments = collect_attachments(
                email_obj.get("bodyStructure"), include_inline=args.include_inline
            )
            attachments_out = args.attachments_out or (os.path.join(args.out, "attachments") if args.out else "attachments")
            for attachment in attachments:
                path = download_attachment(
                    client, attachment, attachments_out, prefix=sanitize_filename(email_obj.get("id") or "")
                )
                downloaded.append(
                    {
                        "emailId": email_obj.get("id"),
                        "name": attachment.get("name") or "",
                        "blobId": attachment.get("blobId"),
                        "type": attachment.get("type") or "",
                        "path": path,
                    }
                )
        if args.format == "json" or args.output == "json":
            text = extract_body(email_obj, prefer="text")
            html = extract_body(email_obj, prefer="html")
            stripped_text, links = extract_text_and_links(html) if html else ("", [])
            payload = {
                "email": email_obj,
                "text": text,
                "html": html,
                "stripped": {"text": stripped_text, "links": links},
                "saved": saved,
                "attachments": attachments,
                "downloaded_attachments": downloaded,
            }
            output_json(payload, pretty=args.pretty)
        else:
            output_read_text(email_obj, args.format)
            if saved:
                print("\nSaved:")
                for item in saved:
                    print(f"{item.get('format')} -> {item.get('path')}")
            if downloaded:
                print("\nDownloaded attachments:")
                for item in downloaded:
                    print(f"{item.get('name')} -> {item.get('path')}")
        return 0

    if args.command == "thread":
        thread_id = resolve_thread_id(client, args.id, args.id_type)
        emails = fetch_thread_emails(
            client,
            thread_id,
            include_bodies=True,
            max_body_bytes=args.max_body_bytes,
            include_body_structure=args.download_attachments,
        )
        saved = []
        downloaded = []
        formats = parse_formats(args.save_formats)
        if args.out or formats:
            formats = formats or ([args.format] if args.format in {"text", "html", "stripped"} else ["text"])
            for email_obj in emails:
                saved.extend(save_email_bodies(email_obj, args.out or ".", formats))
        if args.download_attachments:
            attachments_out = args.attachments_out or (os.path.join(args.out, "attachments") if args.out else "attachments")
            for email_obj in emails:
                attachments = collect_attachments(
                    email_obj.get("bodyStructure"), include_inline=args.include_inline
                )
                email_dir = attachments_dir_for_email(attachments_out, email_obj)
                for attachment in attachments:
                    path = download_attachment(
                        client, attachment, email_dir, prefix=sanitize_filename(email_obj.get("id") or "")
                    )
                    downloaded.append(
                        {
                            "emailId": email_obj.get("id"),
                            "name": attachment.get("name") or "",
                            "blobId": attachment.get("blobId"),
                            "type": attachment.get("type") or "",
                            "path": path,
                        }
                    )
        if args.format == "json" or args.output == "json":
            thread_payload = []
            for email_obj in emails:
                text = extract_body(email_obj, prefer="text")
                html = extract_body(email_obj, prefer="html")
                stripped_text, links = extract_text_and_links(html) if html else ("", [])
                thread_payload.append(
                    {
                        "email": email_obj,
                        "text": text,
                        "html": html,
                        "stripped": {"text": stripped_text, "links": links},
                    }
                )
            payload = {
                "threadId": thread_id,
                "count": len(emails),
                "messages": thread_payload,
                "saved": saved,
                "downloaded_attachments": downloaded,
            }
            output_json(payload, pretty=args.pretty)
        else:
            output_thread_text(emails, args.format)
            if saved:
                print("\nSaved:")
                for item in saved:
                    print(f"{item.get('format')} -> {item.get('path')}")
            if downloaded:
                print("\nDownloaded attachments:")
                for item in downloaded:
                    print(f"{item.get('name')} -> {item.get('path')}")
        return 0

    if args.command == "attachments":
        items = get_emails(client, [args.email_id], include_bodies=False, extra_props=["bodyStructure"])
        if not items:
            raise RuntimeError(f"Email not found: {args.email_id}")
        email_obj = items[0]
        attachments = collect_attachments(
            email_obj.get("bodyStructure"), include_inline=args.include_inline
        )
        downloaded = []
        if args.download:
            attachments_out = args.out or "attachments"
            for attachment in attachments:
                path = download_attachment(
                    client, attachment, attachments_out, prefix=sanitize_filename(email_obj.get("id") or "")
                )
                downloaded.append(
                    {
                        "emailId": email_obj.get("id"),
                        "name": attachment.get("name") or "",
                        "blobId": attachment.get("blobId"),
                        "type": attachment.get("type") or "",
                        "path": path,
                    }
                )
        if args.output == "json":
            payload = {
                "emailId": email_obj.get("id"),
                "attachments": attachments,
                "downloaded_attachments": downloaded,
            }
            output_json(payload, pretty=args.pretty)
        else:
            output_attachments_text(attachments, downloaded=downloaded)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
