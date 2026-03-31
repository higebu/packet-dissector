//! HPACK static table (RFC 7541, Appendix A).

/// A static table entry with header name and optional value.
pub struct StaticEntry {
    /// Header name (always lowercase for pseudo-headers with leading ':').
    pub name: &'static str,
    /// Header value (empty string if the entry has no predefined value).
    pub value: &'static str,
}

/// RFC 7541 Appendix A — the 61 pre-defined header field entries.
/// Index is 1-based: `STATIC_TABLE[0]` corresponds to index 1.
pub static STATIC_TABLE: [StaticEntry; 61] = [
    StaticEntry {
        name: ":authority",
        value: "",
    }, // 1
    StaticEntry {
        name: ":method",
        value: "GET",
    }, // 2
    StaticEntry {
        name: ":method",
        value: "POST",
    }, // 3
    StaticEntry {
        name: ":path",
        value: "/",
    }, // 4
    StaticEntry {
        name: ":path",
        value: "/index.html",
    }, // 5
    StaticEntry {
        name: ":scheme",
        value: "http",
    }, // 6
    StaticEntry {
        name: ":scheme",
        value: "https",
    }, // 7
    StaticEntry {
        name: ":status",
        value: "200",
    }, // 8
    StaticEntry {
        name: ":status",
        value: "204",
    }, // 9
    StaticEntry {
        name: ":status",
        value: "206",
    }, // 10
    StaticEntry {
        name: ":status",
        value: "304",
    }, // 11
    StaticEntry {
        name: ":status",
        value: "400",
    }, // 12
    StaticEntry {
        name: ":status",
        value: "404",
    }, // 13
    StaticEntry {
        name: ":status",
        value: "500",
    }, // 14
    StaticEntry {
        name: "accept-charset",
        value: "",
    }, // 15
    StaticEntry {
        name: "accept-encoding",
        value: "gzip, deflate",
    }, // 16
    StaticEntry {
        name: "accept-language",
        value: "",
    }, // 17
    StaticEntry {
        name: "accept-ranges",
        value: "",
    }, // 18
    StaticEntry {
        name: "accept",
        value: "",
    }, // 19
    StaticEntry {
        name: "access-control-allow-origin",
        value: "",
    }, // 20
    StaticEntry {
        name: "age",
        value: "",
    }, // 21
    StaticEntry {
        name: "allow",
        value: "",
    }, // 22
    StaticEntry {
        name: "authorization",
        value: "",
    }, // 23
    StaticEntry {
        name: "cache-control",
        value: "",
    }, // 24
    StaticEntry {
        name: "content-disposition",
        value: "",
    }, // 25
    StaticEntry {
        name: "content-encoding",
        value: "",
    }, // 26
    StaticEntry {
        name: "content-language",
        value: "",
    }, // 27
    StaticEntry {
        name: "content-length",
        value: "",
    }, // 28
    StaticEntry {
        name: "content-location",
        value: "",
    }, // 29
    StaticEntry {
        name: "content-range",
        value: "",
    }, // 30
    StaticEntry {
        name: "content-type",
        value: "",
    }, // 31
    StaticEntry {
        name: "cookie",
        value: "",
    }, // 32
    StaticEntry {
        name: "date",
        value: "",
    }, // 33
    StaticEntry {
        name: "etag",
        value: "",
    }, // 34
    StaticEntry {
        name: "expect",
        value: "",
    }, // 35
    StaticEntry {
        name: "expires",
        value: "",
    }, // 36
    StaticEntry {
        name: "from",
        value: "",
    }, // 37
    StaticEntry {
        name: "host",
        value: "",
    }, // 38
    StaticEntry {
        name: "if-match",
        value: "",
    }, // 39
    StaticEntry {
        name: "if-modified-since",
        value: "",
    }, // 40
    StaticEntry {
        name: "if-none-match",
        value: "",
    }, // 41
    StaticEntry {
        name: "if-range",
        value: "",
    }, // 42
    StaticEntry {
        name: "if-unmodified-since",
        value: "",
    }, // 43
    StaticEntry {
        name: "last-modified",
        value: "",
    }, // 44
    StaticEntry {
        name: "link",
        value: "",
    }, // 45
    StaticEntry {
        name: "location",
        value: "",
    }, // 46
    StaticEntry {
        name: "max-forwards",
        value: "",
    }, // 47
    StaticEntry {
        name: "proxy-authenticate",
        value: "",
    }, // 48
    StaticEntry {
        name: "proxy-authorization",
        value: "",
    }, // 49
    StaticEntry {
        name: "range",
        value: "",
    }, // 50
    StaticEntry {
        name: "referer",
        value: "",
    }, // 51
    StaticEntry {
        name: "refresh",
        value: "",
    }, // 52
    StaticEntry {
        name: "retry-after",
        value: "",
    }, // 53
    StaticEntry {
        name: "server",
        value: "",
    }, // 54
    StaticEntry {
        name: "set-cookie",
        value: "",
    }, // 55
    StaticEntry {
        name: "strict-transport-security",
        value: "",
    }, // 56
    StaticEntry {
        name: "transfer-encoding",
        value: "",
    }, // 57
    StaticEntry {
        name: "user-agent",
        value: "",
    }, // 58
    StaticEntry {
        name: "vary",
        value: "",
    }, // 59
    StaticEntry {
        name: "via",
        value: "",
    }, // 60
    StaticEntry {
        name: "www-authenticate",
        value: "",
    }, // 61
];

/// Look up a static table entry by 1-based index.
/// Returns `None` for index 0 or indices beyond 61 (dynamic table range).
pub fn lookup(index: usize) -> Option<&'static StaticEntry> {
    if index == 0 || index > STATIC_TABLE.len() {
        return None;
    }
    Some(&STATIC_TABLE[index - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_authority() {
        let entry = lookup(1).unwrap();
        assert_eq!(entry.name, ":authority");
        assert_eq!(entry.value, "");
    }

    #[test]
    fn lookup_method_get() {
        let entry = lookup(2).unwrap();
        assert_eq!(entry.name, ":method");
        assert_eq!(entry.value, "GET");
    }

    #[test]
    fn lookup_status_200() {
        let entry = lookup(8).unwrap();
        assert_eq!(entry.name, ":status");
        assert_eq!(entry.value, "200");
    }

    #[test]
    fn lookup_last_entry() {
        let entry = lookup(61).unwrap();
        assert_eq!(entry.name, "www-authenticate");
    }

    #[test]
    fn lookup_zero_returns_none() {
        assert!(lookup(0).is_none());
    }

    #[test]
    fn lookup_beyond_static_returns_none() {
        assert!(lookup(62).is_none());
    }
}
