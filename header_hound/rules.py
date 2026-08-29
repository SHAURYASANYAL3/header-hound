"""
Security header definitions and evaluation rules.
Separating rules from logic makes it trivial to add new checks later.
"""

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "Prevents the browser from accessing the site over HTTP.",
        "recommendation": "Set to 'max-age=31536000; includeSubDomains'."
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Prevents cross-site scripting (XSS) and data injection attacks.",
        "recommendation": "Implement a strict CSP restricting unsafe-inline and eval."
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME-sniffing a response away from the declared content-type.",
        "expected": "nosniff",
        "recommendation": "Set to 'nosniff'."
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Protects against clickjacking attacks.",
        "recommendation": "Set to 'DENY' or 'SAMEORIGIN'."
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Controls how much referrer information should be included with requests.",
        "recommendation": "Set to 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "required": False, 
        "description": "Allows fine-grained control over which browser features can be used.",
        "recommendation": "Explicitly disable unneeded APIs (e.g., geolocation=(), microphone=())."
    }
}

INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-PHP-Version"
]
