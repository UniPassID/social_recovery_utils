pub fn to_0x_hex<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    let mut res = String::from("0x");
    res += &hex::encode(data);
    res
}

pub fn from_0x_hex(input: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(input.trim_start_matches("0x"))?)
}