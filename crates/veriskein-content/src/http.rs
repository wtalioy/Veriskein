#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyFrame {
    Complete { body: Vec<u8>, consumed: usize },
    Incomplete,
    NotHttp,
}

pub(crate) fn parse_body_frame(bytes: &[u8]) -> BodyFrame {
    if !looks_like_http(bytes) {
        return BodyFrame::NotHttp;
    }

    let Some((header_end, separator_len)) = find_header_end(bytes) else {
        return BodyFrame::Incomplete;
    };

    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let body_start = header_end + separator_len;
    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok());
    let chunked = header_value(&headers, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if chunked {
        return decode_chunked(&bytes[body_start..], body_start);
    }

    let Some(content_length) = content_length else {
        return BodyFrame::Complete {
            body: Vec::new(),
            consumed: body_start,
        };
    };

    let end = body_start.saturating_add(content_length);
    if bytes.len() < end {
        return BodyFrame::Incomplete;
    }

    BodyFrame::Complete {
        body: bytes[body_start..end].to_vec(),
        consumed: end,
    }
}

fn looks_like_http(bytes: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"HTTP/",
    ];

    METHODS.iter().any(|method| {
        bytes.len() >= method.len() && bytes[..method.len()].eq_ignore_ascii_case(method)
    })
}

fn find_header_end(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| (pos, 4))
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|pos| (pos, 2))
        })
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then_some(value)
    })
}

fn decode_chunked(bytes: &[u8], body_start: usize) -> BodyFrame {
    let mut cursor = 0;
    let mut body = Vec::new();

    loop {
        let Some((line, line_len)) = read_line(&bytes[cursor..]) else {
            return BodyFrame::Incomplete;
        };
        cursor += line_len;

        let size_hex = line.split(';').next().unwrap_or(line).trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            return BodyFrame::Complete {
                body,
                consumed: body_start + cursor,
            };
        };

        if size == 0 {
            if bytes.get(cursor..cursor + 2) == Some(b"\r\n") {
                cursor += 2;
            } else if bytes.get(cursor..cursor + 1) == Some(b"\n") {
                cursor += 1;
            }
            return BodyFrame::Complete {
                body,
                consumed: body_start + cursor,
            };
        }

        if bytes.len() < cursor + size {
            return BodyFrame::Incomplete;
        }
        body.extend_from_slice(&bytes[cursor..cursor + size]);
        cursor += size;

        if bytes.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        } else if bytes.get(cursor..cursor + 1) == Some(b"\n") {
            cursor += 1;
        } else {
            return BodyFrame::Incomplete;
        }
    }
}

fn read_line(bytes: &[u8]) -> Option<(&str, usize)> {
    let lf = bytes.iter().position(|byte| *byte == b'\n')?;
    let line_bytes = if lf > 0 && bytes[lf - 1] == b'\r' {
        &bytes[..lf - 1]
    } else {
        &bytes[..lf]
    };
    let line = core::str::from_utf8(line_bytes).ok()?;
    Some((line, lf + 1))
}
