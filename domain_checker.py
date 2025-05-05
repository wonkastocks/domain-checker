import time
import whois
import datetime  # Need this for date formatting

# List of TLDs known to sometimes cause issues or timeouts with python-whois
# You might need to adjust this list based on experience
# Reference: Observed behavior and potential library limitations
KNOWN_PROBLEMATIC_TLDS = {'.io', '.co', '.ai', '.gg', '.so', '.is'}


def format_date(date_obj):
    """Helper function to format date/datetime objects for display.
    
    Handles cases where WHOIS library returns a list of dates or different date/time types.
    Takes the first element if it's a list.
    """
    if isinstance(date_obj, list):
        # Take the first date if it's a list (common occurrence in whois data)
        date_obj = date_obj[0] if date_obj else None # Handle empty list
    
    if isinstance(date_obj, datetime.datetime):
        return date_obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(date_obj, datetime.date):
        return date_obj.strftime('%Y-%m-%d')
    return str(date_obj) # Fallback if it's not a recognized date/time object or None

def check_domain(domain_name, tld):
    """Checks the availability and WHOIS details of a single domain.

    Args:
        domain_name (str): The base domain name (e.g., 'example').
        tld (str): The top-level domain, including the dot (e.g., '.com').

    Returns:
        dict: A dictionary containing 'status' ('Registered', 'Available', 'Error', 'Skipped')
              and potentially 'registrar', 'creation_date', 'updated_date', 'message' (for errors).
    """
    full_domain = f"{domain_name}{tld}"
    result = {'status': 'Unknown'} # Initialize result dictionary

    # Skip TLDs known to cause problems with the current library to avoid long waits/errors
    if tld.lower() in KNOWN_PROBLEMATIC_TLDS:
        print(f"[*] Skipping {full_domain} (known problematic TLD with this library)")
        result['status'] = 'Skipped'
        return result

    try:
        print(f"[*] Checking {full_domain}...")
        # Perform the WHOIS lookup
        w = whois.whois(full_domain)

        # --- Determine Status based on WHOIS response --- 
        # The python-whois library's behavior varies. 
        # Presence of 'domain_name' usually indicates registration.
        # Absence or specific exceptions often indicate availability.
        if w.domain_name:
            # Domain appears registered, extract details if possible
            result['status'] = 'Registered'
            result['registrar'] = w.registrar if hasattr(w, 'registrar') and w.registrar else 'N/A'
            # Use helper to format dates, handling missing attributes and potential lists
            result['creation_date'] = format_date(w.creation_date) if hasattr(w, 'creation_date') else 'N/A'
            result['updated_date'] = format_date(w.updated_date) if hasattr(w, 'updated_date') else 'N/A'
            # Note: Registrant name/org is often redacted due to privacy policies.
        else:
            # No domain_name found, likely available (though not guaranteed)
            result['status'] = 'Available'

    except whois.parser.PywhoisError as e:
        # Handle specific errors from the WHOIS library that indicate availability
        error_str = str(e).lower()
        if "no match for" in error_str or "no whois server is known for" in error_str or "domain not found" in error_str:
            result['status'] = 'Available'
        else:
            # Other WHOIS parsing errors
            print(f"[!] WHOIS Error checking {full_domain}: {e}")
            result['status'] = 'Error'
            result['message'] = str(e)
    except Exception as e:
        # Catch other potential exceptions (e.g., network issues, timeouts, unexpected data)
        print(f"[!] Unexpected error checking {full_domain}: {e}")
        result['status'] = 'Error'
        result['message'] = str(e)

    return result

def main():
    print("Domain Availability Checker")
    print("---------------------------")

    # --- Input Stage --- 
    # Get the domain/base name from the user
    name_input = input("Enter the full domain (e.g., google.com) OR base name (e.g., google) to check: ").strip().lower()
    # Delay is now fixed to 1 second to avoid prompt and be polite to WHOIS servers
    delay = 1.0

    # Initialize variables
    base_name = name_input
    original_tld = None
    tlds_to_check = set() # Using a set prevents duplicate TLD checks
    process_further_tlds = True # Flag to determine if we need to ask for/use default TLDs

    # Basic input validation
    if not name_input:
        print("Error: Domain or base name cannot be empty.")
        return

    # --- Determine Base Name and TLDs to Check --- 
    # Check if the input contains a dot, suggesting a full domain was entered
    if '.' in name_input:
        # Split only on the last dot to handle potential subdomains (though we use the first part)
        parts = name_input.rsplit('.', 1)
        # Check if the split resulted in two non-empty parts (basic format check)
        if len(parts) == 2 and parts[0] and parts[1]: 
            base_name = parts[0]
            original_tld = '.' + parts[1]
            # If a full domain was provided, only check this specific TLD by default
            tlds_to_check.add(original_tld)
            process_further_tlds = False # Skip asking for additional TLDs
        else:
             # Handle cases like '.' or 'domain.' - treat as base name
             print(f"Warning: Input '{name_input}' contains '.' but doesn't look like name.tld. Treating as base name.")
             base_name = name_input 
             # process_further_tlds remains True, so we'll ask for TLDs below
    else:
        # Input was just a base name (no dot found)
        base_name = name_input
        # process_further_tlds remains True

    # Ask for TLDs only if a base name was given OR the input format was ambiguous
    if process_further_tlds:
        additional_tlds_input = input("Enter TLDs to check (e.g., .com .org .net - leave blank for defaults): ").strip()
        if additional_tlds_input:
            # Process the entered TLDs: ensure they start with '.', convert to lowercase, add to set
            additional_tlds = {tld.strip() if tld.strip().startswith('.') else '.' + tld.strip().lower() 
                               for tld in additional_tlds_input.split()
                               if tld.strip()} # Filter out empty strings from multiple spaces
            tlds_to_check.update(additional_tlds)
        else:
            # No additional TLDs provided for a base name, use default list
            tlds_to_check = {'.com', '.net', '.org'} # Default TLDs
            print("No TLDs specified, using defaults: .com, .net, .org")

    # --- Execution Stage --- 
    # Convert the set of TLDs to a sorted list for consistent checking order
    tlds_list = sorted(list(tlds_to_check))
    
    # Print summary of what will be checked
    print(f"\nChecking base name: {base_name}")
    print(f"Against TLDs: {', '.join(tlds_list)}")
    print(f"Delay: {delay}s\n")

    # Dictionary to store results (optional, mainly for potential future summary)
    results = {}
    
    # Loop through each TLD to check
    for i, tld in enumerate(tlds_list):
        # Basic check to skip empty/invalid TLD entries
        if not tld:
            print(f"Skipping invalid TLD entry.")
            continue
            
        # Construct the full domain name for this iteration
        full_domain_to_check = f"{base_name}{tld}"
        
        # Call the function to perform the check
        result_data = check_domain(base_name, tld)
        results[full_domain_to_check] = result_data
        
        # --- Print Intermediate Results --- 
        print(f"  -> Status: {result_data['status']}")
        if result_data['status'] == 'Registered':
            # Print details if registered
            print(f"     Registrar: {result_data.get('registrar', 'N/A')}")
            print(f"     Created:   {result_data.get('creation_date', 'N/A')}")
            print(f"     Updated:   {result_data.get('updated_date', 'N/A')}")
        elif result_data['status'] == 'Error':
            # Print error message if applicable
             print(f"     Error Msg: {result_data.get('message', 'Unknown error')}")

        # Apply delay between checks unless it's the last TLD or was skipped
        if result_data['status'] != 'Skipped' and i < len(tlds_list) - 1:
            print(f"[*] Waiting {delay}s...")
            time.sleep(delay)
            
        # Print separator between checks
        print("---")

    # Final note to the user
    print("\nNote: WHOIS data accuracy varies. 'Available' might still be premium/reserved.")

# Standard Python entry point check
if __name__ == "__main__":
    main()
