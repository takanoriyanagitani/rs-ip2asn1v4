use rs_ip2asn1v4::TinyIpSetsC0;

fn sub() -> Result<(), Box<dyn std::error::Error>> {
    let dummy_flags: u8 = (TinyIpSetsC0::V1 | TinyIpSetsC0::V3 | TinyIpSetsC0::V5).bits();
    println!("Flags as string: {}", TinyIpSetsC0::to_string(dummy_flags));

    let der: Vec<u8> = TinyIpSetsC0::raw2der_bytes(dummy_flags)?;
    println!("DER bytes: {:?}", der);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    sub()
}
