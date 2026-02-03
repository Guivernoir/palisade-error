use palisade_errors::{
    ContextBuilder, DualContextError, OperationCategory, 
    SocAccess, definitions
};

/// Simulates a vulnerable endpoint in a honeypot
fn handle_admin_login(username: &str) -> Result<(), DualContextError> {
    // Detect SQL Injection signature
    if username.contains("' OR '1'='1") {
        // We want to lie to the attacker to make them think the DB failed naturally,
        // rather than telling them "WAF Blocked You".
        
        return Err(ContextBuilder::new()
            // THE LIE: Generic database connection error
            .public_lie("Database connection pool exhausted. Please try again later.")
            
            // THE TRUTH + SENSITIVE DATA: 
            // We must combine diagnostic info and the payload into a single SENSITIVE context.
            // You cannot set .internal_diagnostic() and .internal_sensitive() separately.
            .internal_sensitive(format!(
                "SQL Injection detected in login payload. Payload: [{}]", 
                username
            ))
            
            // CATEGORY: Deception (displayed as 'Routine Operation' externally)
            .category(OperationCategory::Deception)
            .build()
        );
    }
    
    Ok(())
}

fn main() {
    println!("--- Honeypot Deception Example ---\n");

    let attack_payload = "admin' OR '1'='1";
    
    match handle_admin_login(attack_payload) {
        Ok(_) => println!("Login successful"),
        Err(e) => {
            // 1. External Output (HTTP Response)
            println!("[HTTP 500 Response Body]");
            println!("Error: {}", e.external_message()); 
            println!("Category: {}\n", e.external_category()); 
            // Output: "Database connection pool exhausted..." / "Routine Operation"

            // 2. Internal Security Log (SIEM)
            println!("[Internal SIEM Log]");
            let internal = e.internal();
            
            // Note: internal.payload() returns None for SENSITIVE contexts to prevent accidental logging.
            // It only returns data for standard DIAGNOSTIC contexts.
            if let Some(payload) = internal.payload() {
                println!("Alert: {}", payload);
            } else {
                println!("Alert: [REDACTED - SENSITIVE DATA HELD]");
            }

            // 3. Sensitive Data Extraction
            // Requires the capability token `SocAccess`
            println!("\n[Forensic Analysis (Requires Clearance)]");
            let clearance = SocAccess::acquire();
            
            if let Some(sensitive_data) = internal.expose_sensitive(&clearance) {
                println!("CRITICAL: {}", sensitive_data);
            } else {
                println!("No sensitive data found.");
            }
        }
    }
}