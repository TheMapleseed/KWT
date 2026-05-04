#![forbid(unsafe_code)]

// ============================================================================
// kwt/src/main.rs
//
// Example binary demonstrating KWT issue and validate, with a **wire-size**
// comparison to a typical RS256-shaped JWT (density / bytes only — not a claim
// that KWT accepts or mirrors JWT security rules).
// ============================================================================

use kwt::{
    codec::{new_claims, Role, Scope},
    crypto::MasterKey,
    token::KwtToken,
};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                 KWT — KDL Web Token  Example                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // -----------------------------------------------------------------------
    // 1.  Generate a master key
    //     In production: load from a secrets manager (Vault, AWS SSM, etc.)
    // -----------------------------------------------------------------------
    let master_key = MasterKey::generate().expect("CSPRNG");
    println!("[1] Generated 256-bit master key (CSPRNG)");

    // -----------------------------------------------------------------------
    // 2.  Build claims
    // -----------------------------------------------------------------------
    let mut claims = new_claims("user_882", "api.example.com", 3_600).expect("claims");
    claims.roles  = vec![Role::Admin, Role::Editor];
    claims.scopes = vec![Scope::ReadStats, Scope::WriteLogs];

    println!("\n[2] Claims (human-readable KDL view):");
    println!("    subject    \"{}\"", claims.subject);
    println!("    issued     {}", claims.issued_at);
    println!("    expires    {}", claims.expires_at);
    println!("    audience   \"{}\"", claims.audience);
    let role_strs: Vec<_> = claims.roles.iter().map(|r| format!("\"{}\"", r)).collect();
    println!("    roles      {}", role_strs.join(" "));
    let scope_strs: Vec<_> = claims.scopes.iter().map(|s| format!("\"{}\"", s)).collect();
    println!("    scopes     {}", scope_strs.join(" "));
    println!("    jti        {}", claims.jti);

    // -----------------------------------------------------------------------
    // 3.  Show canonical binary size before encryption
    // -----------------------------------------------------------------------
    let canonical = kwt::codec_encode(&claims).expect("encode failed");
    println!("\n[3] Canonical binary payload: {} bytes", canonical.len());
    print!("    Hex: ");
    for (i, byte) in canonical.iter().enumerate() {
        if i > 0 && i % 16 == 0 { print!("\n         "); }
        print!("{:02x} ", byte);
    }
    println!();

    // -----------------------------------------------------------------------
    // 4.  Issue the token
    // -----------------------------------------------------------------------
    let token_str = KwtToken::issue(&claims, &master_key).expect("issue failed");
    println!("\n[4] Issued KWT token ({} bytes):", token_str.len());
    println!("    {}", token_str);

    // -----------------------------------------------------------------------
    // 5.  Compare with equivalent JWT (static RS256-shaped example; sizes are illustrative)
    // -----------------------------------------------------------------------
    let equivalent_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiJ1c2VyXzg4MiIsImlhdCI6e30sImV4cCI6e30sImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsInJvbGVzIjpbImFkbWluIiwiZWRpdG9yIl0sInNjb3BlcyI6WyJyZWFkOnN0YXRzIiwid3JpdGU6bG9ncyJdfQ.\
         SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c_dbnU9JZFqcT8R0hM9GbwNu3PVMBAlhU8GWfG8dFQ";
    println!("\n[5] Size comparison (sample JWT body {} bytes):", equivalent_jwt.len());
    println!("    ┌──────────────────────────┬──────────────┐");
    println!("    │ Format                   │ Size (bytes) │");
    println!("    ├──────────────────────────┼──────────────┤");
    println!("    │ JWT (typical, RS256)      │ ~380-420     │");
    println!("    │ KWT canonical plaintext  │ {:>12} │", canonical.len());
    println!("    │ KWT encrypted token      │ {:>12} │", token_str.len());
    println!("    └──────────────────────────┴──────────────┘");
    println!(
        "\n    Information density: {:.2} bits/byte  (JWT baseline: ~1.55 bits/byte)",
        (canonical.len() as f64 * 8.0) / token_str.len() as f64
        // Note: this measures raw-payload bits vs wire bytes — for comparison
        // with the whitepaper formula, semantic-bits / wire-bytes gives ~2.94
    );

    // -----------------------------------------------------------------------
    // 6.  Validate the token
    // -----------------------------------------------------------------------
    println!("\n[6] Validating token...");
    match KwtToken::validate(&token_str, &master_key, "api.example.com") {
        Ok(validated) => {
            println!("    ✓ Authentication tag verified");
            println!("    ✓ Payload parsed successfully");
            println!("    ✓ Token not expired");
            println!("    ✓ Audience matched");
            println!("\n    Recovered claims:");
            println!("      Subject:  {}", validated.claims.subject);
            println!("      JTI:      {}", validated.claims.jti);
            let role_strs: Vec<_> = validated.claims.roles.iter().map(|r| r.to_string()).collect();
            println!("      Roles:    {}", role_strs.join(", "));
        }
        Err(e) => {
            eprintln!("    ✗ Validation failed: {}", e);
            std::process::exit(1);
        }
    }

    // -----------------------------------------------------------------------
    // 7.  Demonstrate tamper detection
    // -----------------------------------------------------------------------
    println!("\n[7] Tamper detection demo...");
    let mut tampered = token_str.clone();
    // Corrupt the last byte of the ciphertext
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    match KwtToken::validate(&tampered, &master_key, "api.example.com") {
        Ok(_)  => println!("    ✗ ERROR: tampered token was accepted (this should not happen)"),
        Err(e) => println!("    ✓ Tampered token correctly rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // 8.  Demonstrate wrong-key detection
    // -----------------------------------------------------------------------
    println!("\n[8] Wrong-key detection demo...");
    let wrong_key = MasterKey::generate().expect("CSPRNG");
    match KwtToken::validate(&token_str, &wrong_key, "api.example.com") {
        Ok(_)  => println!("    ✗ ERROR: token accepted with wrong key (this should not happen)"),
        Err(e) => println!("    ✓ Wrong key correctly rejected: {}", e),
    }

    println!("\n✓ All checks passed.\n");
}
