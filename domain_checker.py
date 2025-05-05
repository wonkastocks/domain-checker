import time
import whois
import datetime  # Need this for date formatting

# List of TLDs known to sometimes cause issues or timeouts with python-whois
# You might need to adjust this list based on experience
KNOWN_PROBLEMATIC_TLDS = {'.io', '.co', '.ai', '.gg', '.so', '.is'}


def format_date(date_obj):
    """Formats date/datetime objects for display, handling lists."""
    if isinstance(date_obj, list):
        # Take the first date if it's a list
        date_obj = date_obj[0]
    if isinstance(date_obj, datetime.datetime):
        return date_obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(date_obj, datetime.date):
        return date_obj.strftime('%Y-%m-%d')
    return str(date_obj) # Fallback

def check_domain(domain_name, tld):
    """Checks the availability of a single domain and returns details.

    Args:
        domain_name (str): The base domain name (e.g., 'example').
        tld (str): The top-level domain (e.g., '.com').

    Returns:
        dict: A dictionary containing 'status' and potentially 'registrar',
              'creation_date', 'updated_date'.
    """
    full_domain = f"{domain_name}{tld}"
    result = {'status': 'Unknown'}

    if tld.lower() in KNOWN_PROBLEMATIC_TLDS:
        print(f"[*] Skipping {full_domain} (known problematic TLD with this library)")
        result['status'] = 'Skipped'
        return result

    try:
        print(f"[*] Checking {full_domain}...")
        w = whois.whois(full_domain)

        if w.domain_name:
            result['status'] = 'Registered'
            result['registrar'] = w.registrar or 'N/A'
            # Handle potential lists for dates
            result['creation_date'] = format_date(w.creation_date) if hasattr(w, 'creation_date') and w.creation_date else 'N/A'
            result['updated_date'] = format_date(w.updated_date) if hasattr(w, 'updated_date') and w.updated_date else 'N/A'
            # Registrant name is often redacted, so we won't rely on it
        else:
            result['status'] = 'Available'

    except whois.parser.PywhoisError as e:
        if "No match for" in str(e) or "No whois server is known for" in str(e) or "Domain not found." in str(e):
            result['status'] = 'Available'
        else:
            print(f"[!] Error checking {full_domain}: {e}")
            result['status'] = 'Error'
            result['message'] = str(e)
    except Exception as e:
        print(f"[!] Unexpected error checking {full_domain}: {e}")
        result['status'] = 'Error'
        result['message'] = str(e)

    return result

def main():
    print("Domain Availability Checker")
    print("---------------------------")

    # --- Input Stage ---
    name_input = input("Enter the full domain (e.g., google.com) OR base name (e.g., google) to check: ").strip().lower()
    # Delay is now fixed
    delay = 1.0

    base_name = name_input
    original_tld = None
    tlds_to_check = set()
    process_further_tlds = True # Flag to determine if we need to ask for/use default TLDs

    if not name_input:
        print("Error: Domain or base name cannot be empty.")
        return

    # --- Determine Base Name and TLDs to Check ---
    if '.' in name_input:
        parts = name_input.rsplit('.', 1)
        if len(parts) == 2 and parts[0] and parts[1]: # Basic check for name.tld format
            base_name = parts[0]
            original_tld = '.' + parts[1]
            # Since a full domain was provided, only check this one TLD
            tlds_to_check.add(original_tld)
            process_further_tlds = False # Don't ask for/use other TLDs
        else:
             print(f"Warning: Input '{name_input}' contains '.' but doesn't look like name.tld. Treating as base name.")
             base_name = name_input # Treat as base name
             # Proceed to ask for TLDs below
    else:
        # Input was just a base name
        base_name = name_input
        # Proceed to ask for TLDs below

    # Ask for TLDs only if a base name was given OR the input format was weird
    if process_further_tlds:
        additional_tlds_input = input("Enter TLDs to check (e.g., .com .org .net - leave blank for defaults): ").strip()
        if additional_tlds_input:
            additional_tlds = {tld.strip() if tld.strip().startswith('.') else '.' + tld.strip().lower() 
                               for tld in additional_tlds_input.split()
                               if tld.strip()}
            tlds_to_check.update(additional_tlds)
        else:
            # No additional TLDs provided for a base name, use defaults
            tlds_to_check = {'.com', '.net', '.org'} # Default TLDs
            print("No TLDs specified, using defaults: .com, .net, .org")

    # --- Execution Stage ---
    tlds_list = sorted(list(tlds_to_check))
    print(f"\nChecking base name: {base_name}")
    print(f"Against TLDs: {', '.join(tlds_list)}")
    print(f"Delay: {delay}s\n")

    results = {}
    for i, tld in enumerate(tlds_list):
        # Check if the combination is valid (avoid checking 'basename.' if TLD is empty somehow)
        if not tld:
            print(f"Skipping invalid TLD entry.")
            continue
            
        full_domain_to_check = f"{base_name}{tld}"
        result_data = check_domain(base_name, tld)
        results[full_domain_to_check] = result_data
        
        # Print intermediate status
        print(f"  -> Status: {result_data['status']}")
        if result_data['status'] == 'Registered':
            print(f"     Registrar: {result_data.get('registrar', 'N/A')}")
            print(f"     Created:   {result_data.get('creation_date', 'N/A')}")
            print(f"     Updated:   {result_data.get('updated_date', 'N/A')}")
        elif result_data['status'] == 'Error':
             print(f"     Error Msg: {result_data.get('message', 'Unknown error')}")

        if result_data['status'] != 'Skipped' and i < len(tlds_list) - 1:
            print(f"[*] Waiting {delay}s...")
            time.sleep(delay)
        print("---")

    # Optional: Print summary at the end (can be redundant with intermediate prints)
    # print("\n======= Final Summary ======")
    # for domain, data in results.items():
    #     print(f"{domain}: {data['status']}")
    # print("=========================")
    print("\nNote: WHOIS data accuracy varies. 'Available' might still be premium/reserved.")

if __name__ == "__main__":
    main()
