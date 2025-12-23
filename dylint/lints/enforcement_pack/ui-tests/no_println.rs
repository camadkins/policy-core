// Test case for NO_PRINTLN lint

fn bad_println() {
    println!("This bypasses PolicyLog");
}

fn bad_eprintln() {
    eprintln!("This also bypasses PolicyLog");
}

fn bad_dbg() {
    let x = 42;
    dbg!(x);
}

// Good: using tracing
fn good_tracing() {
    tracing::info!("Structured logging");
}

fn main() {
    bad_println();
    bad_eprintln();
    bad_dbg();
    good_tracing();
}
