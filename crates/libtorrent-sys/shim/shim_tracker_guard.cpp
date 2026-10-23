// shim_tracker_guard.cpp — the tracker guard: whether every tracker an add
// would announce to is on a profile's domains, and under its account prefixes.
// shim_internal.h says why the shim exists and how it is laid out.

#include "shim_internal.h"

using namespace lt_shim;

namespace {

// A host or domain in the one spelling they are compared in: ASCII
// lowercase, without surrounding spaces or a trailing root dot.
std::string canonical_host(std::string s) {
    auto const first = s.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    s.erase(0, first);
    s.erase(s.find_last_not_of(" \t") + 1);
    while (!s.empty() && s.back() == '.') s.pop_back();
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// Both arguments canonical. `host` is `domain` or a subdomain of it.
bool host_matches_domain(const std::string& host, const std::string& domain) {
    if (domain.empty()) return false;
    if (host == domain) return true;
    if (host.size() > domain.size() + 1) {
        const std::string suffix = "." + domain;
        if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
    }
    return false;
}

// Whether libtorrent, announcing to `url`, connects to a host on one of
// `domains`. The host is read with libtorrent's own URL parser — the one its
// tracker connections resolve — so userinfo, a port and IPv6 brackets are
// read as the announce reads them. A URL it cannot read is never allowed.
bool tracker_url_allowed(const std::string& url, const std::vector<std::string>& domains) {
    lt::error_code ec;
    std::string const host = canonical_host(std::get<2>(lt::parse_url_components(url, ec)));
    if (ec || host.empty()) return false;
    for (auto const& d : domains) {
        if (host_matches_domain(host, d)) return true;
    }
    return false;
}

char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Whether `url` is announced under the announce-URL prefix `prefix`: the
// account binding a profile's `allowed_tracker_urls` states, since a private
// tracker puts the account's passkey in the path or query that the host
// check above never reads.
//
// `prefix` is `scheme://authority/...`. Its scheme and authority are compared
// case-insensitively and must equal the URL's exactly, which the `/` closing
// the authority enforces: a URL with userinfo, another port or a longer host
// differs before it. Everything after is compared byte for byte, and must end
// at a boundary, so `?passkey=a` does not admit `?passkey=ab`: either the
// prefix itself ends in `/`, `?` or `&`, or the URL ends with it or goes on
// with one of `/?&#;`. A prefix of any other shape matches nothing.
bool announce_url_has_prefix(const std::string& url, const std::string& prefix) {
    auto const sep = prefix.find("://");
    if (sep == std::string::npos || sep == 0) return false;
    auto const path = prefix.find('/', sep + 3);
    if (path == std::string::npos || path == sep + 3) return false;
    if (url.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < path; ++i) {
        if (ascii_lower(url[i]) != ascii_lower(prefix[i])) return false;
    }
    if (url.compare(path, prefix.size() - path, prefix, path, std::string::npos) != 0)
        return false;
    if (url.size() == prefix.size()) return true;
    auto const is_one_of = [](char c, const char* set) {
        return std::strchr(set, c) != nullptr;
    };
    return is_one_of(prefix.back(), "/?&") || is_one_of(url[prefix.size()], "/?&#;");
}

bool tracker_url_bound(const std::string& url, const std::vector<std::string>& prefixes) {
    for (auto const& p : prefixes) {
        if (announce_url_has_prefix(url, p)) return true;
    }
    return false;
}

}  // namespace

extern "C" int lt_announce_url_has_prefix(const char* url, const char* prefix) {
    if (!url || !prefix) return 0;
    LT_SHIM_TRY
    return announce_url_has_prefix(url, prefix) ? 1 : 0;
    LT_SHIM_CATCH(nullptr, 0, 0)
}

extern "C" int lt_add_trackers_allowed(const char* magnet_uri,
                                       const uint8_t* torrent_buf, size_t torrent_len,
                                       const char* const* tracker_urls,
                                       const int* tracker_tiers, size_t num_trackers,
                                       const uint8_t* resume_buf, size_t resume_len,
                                       const char* domains_csv,
                                       const char* const* url_prefixes, size_t num_prefixes,
                                       char* err_out, int err_len)
{
    if (!domains_csv || (num_prefixes > 0 && !url_prefixes)) {
        set_err(err_out, err_len, "null arg");
        return LT_ERR;
    }
    LT_SHIM_TRY
    std::vector<std::string> domains;
    {
        std::string cur;
        for (const char* p = domains_csv;; ++p) {
            if (*p == ',' || *p == '\0') {
                std::string d = canonical_host(cur);
                if (!d.empty()) domains.push_back(std::move(d));
                cur.clear();
                if (*p == '\0') break;
            } else {
                cur += *p;
            }
        }
    }

    // Built exactly as the matching lt_add_torrent_* builds it, so the
    // trackers read below are the ones the add would hand libtorrent.
    lt::add_torrent_params atp;
    lt::error_code ec;
    if (resume_buf && resume_len > 0) {
        atp = lt::read_resume_data(
            lt::span<char const>(reinterpret_cast<const char*>(resume_buf), resume_len), ec);
        if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
        if (!atp.ti && torrent_buf && torrent_len > 0) {
            atp.ti = std::make_shared<lt::torrent_info>(
                reinterpret_cast<const char*>(torrent_buf), buffer_len(torrent_len));
        }
    } else if (magnet_uri) {
        atp = lt::parse_magnet_uri(magnet_uri, ec);
        if (ec) { set_err(err_out, err_len, ec.message()); return LT_ERR; }
    } else if (torrent_buf && torrent_len > 0) {
        atp.ti = std::make_shared<lt::torrent_info>(
            reinterpret_cast<const char*>(torrent_buf), buffer_len(torrent_len));
        apply_tracker_override(atp, tracker_urls, tracker_tiers, num_trackers);
    } else {
        set_err(err_out, err_len, "no torrent source");
        return LT_ERR;
    }

    // The announce list torrent::torrent() assembles: the metadata's trackers
    // unless the params override them (resume data with a `trackers` list
    // always does, as does a .torrent add given trackers of its own), then
    // every tracker the params carry — a magnet's `tr=`, or either list.
    std::vector<std::string> urls;
    if (atp.ti && !(atp.flags & lt::torrent_flags::override_trackers)) {
        for (auto const& ae : atp.ti->trackers()) urls.push_back(ae.url);
    }
    for (auto const& url : atp.trackers) {
        if (!url.empty()) urls.push_back(url);
    }
    if (urls.empty()) return LT_NO_TRACKERS;
    for (auto const& url : urls) {
        if (!tracker_url_allowed(url, domains)) return 0;
    }
    // Every host is allowed; with an account binding, every URL must also be
    // announced under one of its prefixes. Checked second, so a foreign
    // tracker is reported as one even where it also misses the binding.
    if (num_prefixes > 0) {
        std::vector<std::string> prefixes;
        for (size_t i = 0; i < num_prefixes; ++i) {
            if (url_prefixes[i] && *url_prefixes[i]) prefixes.emplace_back(url_prefixes[i]);
        }
        for (auto const& url : urls) {
            if (!tracker_url_bound(url, prefixes)) return LT_TRACKER_ACCOUNT_MISMATCH;
        }
    }
    return 1;
    LT_SHIM_CATCH(err_out, err_len, LT_ERR)
}
