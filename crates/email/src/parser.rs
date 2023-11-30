use email_rs::{dkim, Email, Header};

use crate::{error::ParserError, types::DkimParams, ParserResult};

fn index_of_sub_array(array: &[u8], sub_array: &[u8], start: usize) -> Option<usize> {
    if sub_array.is_empty() {
        return None;
    }
    array[start..]
        .windows(sub_array.len())
        .position(|window| window == sub_array)
        .map(|v| v + start)
}

fn parse_header(
    dkim_msg: &[u8],
    dkim_header: &Header,
    dkim_sig: Vec<u8>,
    from: String,
) -> ParserResult<DkimParams> {
    let from_index = match index_of_sub_array(dkim_msg, b"from:", 0) {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let from_end_index = match index_of_sub_array(&dkim_msg[from_index..], b"\r\n", from_index) {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let from_left_index =
        match index_of_sub_array(&dkim_msg, format!("<{}>", from).as_bytes(), from_index) {
            Some(index) => {
                if index < from_end_index {
                    index + 1
                } else {
                    match index_of_sub_array(dkim_msg, from.as_bytes(), 0) {
                        Some(index) => index,
                        None => return Err(ParserError::HeaderFormatError),
                    }
                }
            }
            None => match index_of_sub_array(dkim_msg, from.as_bytes(), 0) {
                Some(index) => index,
                None => return Err(ParserError::HeaderFormatError),
            },
        };

    let from_right_index = from_left_index + from.len() - 1;

    let subject_index = match index_of_sub_array(dkim_msg, b"subject:", 0) {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let subject_right_index = match index_of_sub_array(&dkim_msg, b"\r\n", subject_index) {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let dkim_header_index = match index_of_sub_array(dkim_msg, b"dkim-signature:", 0) {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let sdid_index = {
        let d_index = match index_of_sub_array(&dkim_msg, b"d=", dkim_header_index) {
            Some(index) => index,
            None => return Err(ParserError::HeaderFormatError),
        };

        match index_of_sub_array(&dkim_msg, dkim_header.sdid.as_bytes(), d_index) {
            Some(index) => index,
            None => return Err(ParserError::HeaderFormatError),
        }
    };

    let sdid_right_index = sdid_index + dkim_header.sdid.len();

    let selector_index = {
        let s_index = match index_of_sub_array(&dkim_msg, b"s=", dkim_header_index) {
            Some(index) => index,
            None => return Err(ParserError::HeaderFormatError),
        };

        match index_of_sub_array(&dkim_msg, dkim_header.selector.as_bytes(), s_index) {
            Some(index) => index,
            None => return Err(ParserError::HeaderFormatError),
        }
    };

    let selector_right_index = selector_index + dkim_header.selector.len();

    Ok(DkimParams {
        email_header: dkim_msg.to_vec(),
        from_index,
        from_left_index,
        from_right_index,
        subject_index,
        subject_right_index,
        dkim_header_index,
        selector_index,
        selector_right_index,
        sdid_index,
        sdid_right_index,
        from,
        dkim_sig,
    })
}

pub fn parse_email_with_domain(email_raw_data: &[u8], domain: &str) -> ParserResult<DkimParams> {
    let s = String::from_utf8_lossy(email_raw_data);
    let email = Email::from_str(&s)?;

    let binding = dkim::Header::new(Default::default(), Default::default());
    let (dkim_msg, dkim_header) = match email
        .get_dkim_message()
        .into_iter()
        .zip(email.dkim_headers.iter())
        .find(|(_dkim_msg, dkim_header)| &dkim_header.sdid == domain)
    {
        Some((dkim_msg, dkim_header)) => (dkim_msg, dkim_header),
        None => (Default::default(), &binding),
    };

    let dkim_msg = dkim_msg.as_bytes();

    let from = email
        .get_header_item("from")
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;
    let dkim_sig = dkim_header.signature.clone();

    let from = Email::<'_>::extract_address_of_from(from)
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    parse_header(dkim_msg, dkim_header, dkim_sig, from)
}

pub fn parse_email(email_raw_data: &[u8]) -> ParserResult<DkimParams> {
    let s = String::from_utf8_lossy(email_raw_data);
    let email = Email::from_str(&s)?;

    let binding = dkim::Header::new(Default::default(), Default::default());
    let (dkim_msg, dkim_header) = match email
        .get_dkim_message()
        .into_iter()
        .zip(email.dkim_headers.iter())
        .find(|(_dkim_msg, _dkim_header)| true)
    {
        Some((dkim_msg, dkim_header)) => (dkim_msg, dkim_header),
        None => (Default::default(), &binding),
    };

    let dkim_msg = dkim_msg.as_bytes();

    let from = email
        .get_header_item("from")
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;
    let dkim_sig = dkim_header.signature.clone();

    let from = Email::<'_>::extract_address_of_from(from)
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    parse_header(dkim_msg, dkim_header, dkim_sig, from)
}
