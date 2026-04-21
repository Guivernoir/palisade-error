use palisade_errors::AgentError;

fn main() {
    let err = AgentError::new(
        100,
        "Request could not be completed",
        "configuration parse failed near primary bootstrap file",
        "/srv/palisade/config/bootstrap.toml",
    );

    println!("display: {err}");
    println!("debug: {err:?}");
}
