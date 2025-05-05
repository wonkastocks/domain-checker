# Domain Availability Checker

A simple Python command-line tool to check the availability of domain names using WHOIS lookups.

## Features

*   Check domain availability interactively.
*   Provide a full domain name (e.g., `example.com`) to check only that specific domain.
*   Provide just a base name (e.g., `example`) and specify TLDs to check (defaults to `.com`, `.net`, `.org` if none are specified).
*   Displays basic registration information (Registrar, Creation Date, Update Date) if a domain is found to be registered.
*   Includes a 1-second delay between checks to respect WHOIS server rate limits.
*   Attempts to identify and report common availability statuses (Registered, Available, Error, Skipped).

## Requirements

*   Python 3
*   `python-whois` library

## Installation

1.  Clone the repository (or download the files):
    ```bash
    git clone https://github.com/wonkastocks/domain-checker.git
    cd domain-checker
    ```
2.  Install the required library:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from your terminal:

```bash
python domain_checker.py
```

The script will prompt you:

1.  **Enter the full domain (e.g., google.com) OR base name (e.g., google) to check:**
    *   If you enter a full domain like `example.com`, it will check only that domain.
    *   If you enter a base name like `example`, it will proceed to the next step.
2.  **(Only if base name was entered) Enter TLDs to check (e.g., .com .org .net - leave blank for defaults):**
    *   Enter the TLDs you want to check, separated by spaces (e.g., `.co.uk .io .dev`).
    *   If you leave this blank, it will default to checking `.com`, `.net`, and `.org`.

The script will then check each domain and print the status and any available registration details.

## Notes

*   WHOIS data formats can vary significantly between registrars and TLDs. The parsing logic might not capture details correctly for all domains.
*   The `python-whois` library sometimes has issues or timeouts with certain TLDs (e.g., `.io`, `.co`). A few common problematic ones are skipped by default to avoid errors.
*   An 'Available' status doesn't guarantee the domain isn't premium or reserved.
