//! The names EzPi handles. Only these go through it; everything else is untouched.
//! (Measured on Türk Telekom: these are DNS-poisoned and SNI-blocked. Roblox's CDN,
//! rbxcdn.com, which serves game assets and the thumbnail images, is not blocked and stays
//! direct, so downloads keep their full speed.)

pub const SUFFIXES: &[&str] = &[
    "roblox.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discord.gift",
    "discord.new",
    "discord.dev",
    "discordstatus.com",
    "dis.gd",
];

/// Whether `host` is one of [`SUFFIXES`] or a subdomain of one.
pub fn matches(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    SUFFIXES.iter().any(|s| {
        h.len() >= s.len()
            && h[h.len() - s.len()..].eq_ignore_ascii_case(s)
            && (h.len() == s.len() || h.as_bytes()[h.len() - s.len() - 1] == b'.')
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn suffix_matching() {
        assert!(super::matches("roblox.com"));
        assert!(super::matches("thumbnails.Roblox.com."));
        assert!(super::matches("gateway.discord.gg"));
        assert!(!super::matches("notroblox.com"));
        assert!(!super::matches("tr.rbxcdn.com"));
        assert!(!super::matches("com"));
    }
}
