use std::collections::HashMap;

use cookie::Cookie;

pub fn parse_cookies(cookies_str: &str) -> HashMap<String, String> {
    cookies_str.split(';')
        .filter_map(|s| Cookie::parse(s.trim().to_owned()).ok())
        .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
        .collect()
}