"""
JSONitizerEngine — stateless PII sanitisation for Elastic JSON logs.

Targeted ECS keys are replaced with category placeholders (<USER_1>, etc.).
Unstructured string values are scanned with regex for email addresses and
AD-style workstation hostnames.  IP address fields are always preserved.
"""

import re

# ---------------------------------------------------------------------------
# Sensitive ECS key sets  (matched against the full dotted traversal path)
# ---------------------------------------------------------------------------

USER_KEYS: frozenset[str] = frozenset(
    {
        # Standard ECS user fields
        "user.name",
        "username",
        "employee_id",
        "full_name",
        "last_name",
        "user.full_name",
        "user.last_name",
        "user.id",
        "winlog.user.name",
        "source.user.name",
        "destination.user.name",
        # Kibana analyst / workflow identity fields
        "kibana.alert.rule.created_by",
        "kibana.alert.rule.updated_by",
        "kibana.alert.workflow_user",
        "kibana.alert.workflow_assignee_ids",
        # M365 Defender process account fields
        "m365_defender.event.initiating_process.account_name",
        "m365_defender.event.initiating_process.account_sid",
        "m365_defender.event.initiating_process.logon_id",
        # ECS aggregated related-user list
        "related.user",
    }
)

EMAIL_KEYS: frozenset[str] = frozenset(
    {
        "email",
        "user.email",
        "email_address",
    }
)

HOST_KEYS: frozenset[str] = frozenset(
    {
        # ECS host identity
        "host.name",
        "host.hostname",
        "host.id",
        # Elastic agent endpoint identity
        "agent.name",
        "agent.id",
        "agent.ephemeral_id",
        "elastic_agent.id",
        # ECS aggregated related-host list
        "related.hosts",
    }
)

ORG_KEYS: frozenset[str] = frozenset(
    {
        "organization.name",
        "org.name",
        # Active Directory / M365 domain and tenant
        "user.domain",
        "m365_defender.event.tenant.name",
        "m365_defender.event.tenant.id",
        "m365_defender.event.machine_group",
        "m365_defender.event.initiating_process.account_domain",
        # Azure infrastructure identifiers
        "azure.eventhub",
        "azure.consumer_group",
        # Data stream namespace (org-specific index namespace)
        "data_stream.namespace",
        "kibana.alert.original_data_stream.namespace",
    }
)

URL_KEYS: frozenset[str] = frozenset(
    {
        "kibana.alert.url",
        "kibana.alert.rule.meta.kibana_siem_app_url",
    }
)

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# RFC 5321-ish email address
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# AD workstation hostnames: WS-12345, LAPTOP-ABCDE, DESKTOP-XYZ99, PC-1A2B
_HOSTNAME_RE = re.compile(
    r"\b((?:WS|LAPTOP|DESKTOP|PC)-[A-Z0-9]{3,})\b",
    re.IGNORECASE,
)

# Windows user profile path — captures username segment from C:\Users\<username>\...
_WINPATH_RE = re.compile(
    r"(?i)(C:\\Users\\)([^\\\/\s\"'<>]{2,})"
)

# Windows Security Identifier — uniquely encodes domain SID + user account RID
_SID_RE = re.compile(
    r"\bS-1-[0-9]-(?:\d+-)*\d+\b"
)

# NetBIOS DOMAIN\username — e.g. CORP\jdoe
# Negative lookahead (?!\\) prevents matching registry/path continuations like CORP\Users\jdoe
_DOMAIN_USER_RE = re.compile(
    r"\b([A-Z][A-Z0-9]{1,14})\\([A-Za-z][A-Za-z0-9._\-]{1,})\b(?!\\)"
)

# Domain/account prefixes that belong to Windows built-ins and must NOT be redacted
_SYSTEM_PREFIXES: frozenset[str] = frozenset(
    {"HKLM", "HKCU", "HKCR", "HKCC", "HKU", "NT", "BUILTIN", "AUTHORITY", "SERVICE"}
)

# Keys whose values are IP addresses and must not be sanitised
_IP_KEY_RE = re.compile(
    r"(^|\.)ip$|^ip$|ip_address|forwarded_ip",
    re.IGNORECASE,
)


class JSONitizerEngine:
    """
    Stateless sanitisation engine.

    Instantiate a **fresh** instance for every sanitisation run to guarantee
    zero cross-contamination between sessions (no persistent mapping storage).
    """

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.counters: dict[str, int] = {
            "USER": 0,
            "EMAIL": 0,
            "HOST": 0,
            "ORG": 0,
            "URL": 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_replacement(self, value: str, category: str) -> str:
        """Return the canonical placeholder for *value*.

        If *value* has been seen before (in any key or regex context) the
        previously assigned placeholder is returned, guaranteeing that the
        same raw value always maps to the same placeholder within a single
        sanitisation run.
        """
        if not value or not value.strip():
            return value
        if value not in self.mapping:
            self.counters[category] += 1
            self.mapping[value] = f"<{category}_{self.counters[category]}>"
        return self.mapping[value]

    def _apply_regex(self, text: str) -> str:
        """Scan an unstructured string and replace all identifying patterns.

        Handles: email addresses, AD workstation hostnames, Windows user
        profile paths, Windows SIDs, and DOMAIN\\username patterns.
        IP addresses are structurally distinct and will never be touched.
        """

        def _sub_email(m: re.Match) -> str:
            return self._get_replacement(m.group(0), "EMAIL")

        def _sub_host(m: re.Match) -> str:
            # Normalise to upper-case so 'WS-12345' and 'ws-12345' share a slot.
            return self._get_replacement(m.group(0).upper(), "HOST")

        def _sub_winpath(m: re.Match) -> str:
            # Keep the "C:\\Users\\" prefix; replace only the username segment.
            return m.group(1) + self._get_replacement(m.group(2), "USER")

        def _sub_sid(m: re.Match) -> str:
            return self._get_replacement(m.group(0), "USER")

        def _sub_domain_user(m: re.Match) -> str:
            if m.group(1) in _SYSTEM_PREFIXES:
                return m.group(0)  # Preserve system/registry paths unchanged.
            return self._get_replacement(m.group(0), "USER")

        text = _EMAIL_RE.sub(_sub_email, text)
        text = _HOSTNAME_RE.sub(_sub_host, text)
        text = _WINPATH_RE.sub(_sub_winpath, text)
        text = _SID_RE.sub(_sub_sid, text)
        text = _DOMAIN_USER_RE.sub(_sub_domain_user, text)
        return text

    @staticmethod
    def _is_ip_key(key: str) -> bool:
        """Return True when *key* identifies an IP address field."""
        return bool(_IP_KEY_RE.search(key))

    @staticmethod
    def _key_matches(current_key: str, key_set: frozenset[str]) -> bool:
        """Return True if *current_key* exactly equals or ends with a target.

        This allows ECS fields nested inside arbitrary parent objects
        (e.g. ``"a.b.c.user.name"`` still matches ``"user.name"``).
        """
        return current_key in key_set or any(
            current_key.endswith(f".{t}") for t in key_set
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(self, data: object, current_key: str = "") -> object:
        """Recursively traverse *data*, replacing sensitive values in-place.

        Parameters
        ----------
        data:
            The JSON-decoded Python object (dict / list / str / int / …).
        current_key:
            The fully-qualified dotted ECS path accumulated during traversal
            (e.g. ``"user.name"`` or ``"winlog.user.name"``).  Pass the
            default empty string for the document root.
        """
        if isinstance(data, dict):
            return {
                k: self.sanitize(
                    v,
                    current_key=f"{current_key}.{k}".lstrip("."),
                )
                for k, v in data.items()
            }

        if isinstance(data, list):
            return [self.sanitize(item, current_key=current_key) for item in data]

        if isinstance(data, str):
            # Never touch IP-valued fields.
            if self._is_ip_key(current_key):
                return data

            if self._key_matches(current_key, USER_KEYS):
                return self._get_replacement(data, "USER")
            if self._key_matches(current_key, EMAIL_KEYS):
                return self._get_replacement(data, "EMAIL")
            if self._key_matches(current_key, HOST_KEYS):
                return self._get_replacement(data, "HOST")
            if self._key_matches(current_key, ORG_KEYS):
                return self._get_replacement(data, "ORG")
            if self._key_matches(current_key, URL_KEYS):
                return self._get_replacement(data, "URL")

            # Unstructured text — apply regex for emails, hostnames, paths, SIDs.
            return self._apply_regex(data)

        # int, float, bool, None — untouched.
        return data
