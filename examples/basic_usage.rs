use palisade_errors::{
    AgentError, definitions, 
    Result, init_session_salt
};

fn load_configuration(path: &str) -> Result<()> {
    // Simulate a failure to parse a configuration file
    if path == "bad_config.toml" {
        return Err(AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "load_configuration",
            "Syntax error at line 42: unexpected EOF"
        ));
    }
    Ok(())
}

fn main() {
    // 1. Initialize Obfuscation (Optional but recommended)
    // This ensures error codes are unique to this session (preventing fingerprinting)
    init_session_salt(12345);

    println!("--- Basic Usage Example ---\n");

    match load_configuration("bad_config.toml") {
        Ok(_) => println!("Success!"),
        Err(err) => {
            // SCENARIO 1: The External User (Attacker/Client)
            // They see a generic message and an obfuscated error code.
            println!("1. [EXTERNAL RESPONSE] What the user sees:");
            println!("   \"{}\"", err); 
            // Output: "Configuration operation failed [permanent] (E-CFG-105)"
            // (Note: 105 is obfuscated from the original CFG_PARSE_FAILED code)

            println!("\n2. [INTERNAL LOG] What the admin sees:");
            // We use the internal log viewer. In a real app, this goes to Splunk/ELK.
            err.with_internal_log(|log| {
                println!("   Code:      {}", log.code()); // Real code or Obfuscated code based on config
                println!("   Category:  {:?}", log.code().category());
                println!("   Operation: {}", log.operation());
                println!("   Details:   {}", log.details());
            });
        }
    }
}