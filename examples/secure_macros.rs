use palisade_errors::{
    config_err, config_err_sensitive, 
    definitions, sanitized, SocAccess
};

fn main() {
    println!("--- Secure Macros & Sanitization Example ---\n");

    // Scenario: User input that is too long or contains control characters
    let malicious_input = "UserInput\nWith\tControl\x1b[31mChars".repeat(50);
    let secret_key = "sk_live_839284928349283948239";

    // 1. Creating a Public Error with Sanitized Input
    // The `sanitized!` macro truncates and cleans the input before it enters the error system.
    let public_err = config_err!(
        &definitions::CFG_INVALID_VALUE,
        "parse_header",
        "Header value invalid: {}",
        sanitized!(malicious_input)
    );

    println!("[External Display]");
    println!("{}", public_err.external_message());
    // Output will show cleaned string and eventual truncation " ...[TRUNCATED]"
    
    // 2. Creating a Sensitive Error
    // Isolates the secret key in the sensitive context, keeping public display safe.
    let sensitive_err = config_err_sensitive!(
        &definitions::CFG_SECURITY_VIOLATION,
        "validate_apikey",
        "Invalid API Key format", // Public sees this
        sanitized!(secret_key)    // Private log sees this (still sanitized for log safety)
    );

    println!("\n[Sensitive Error Handling]");
    println!("Public:    {}", sensitive_err.external_message());
    
    let internal = sensitive_err.internal();
    
    // Demonstrate that payload() returns None for sensitive contexts
    println!("Payload:   {:?}", internal.payload()); 
    
    // Demonstrate Access
    let clearance = SocAccess::acquire();
    println!("Exposed:   {:?}", internal.expose_sensitive(&clearance));
}