import assertString from './util/assertString';

import isFQDN from './isFQDN';
import isIP from './isIP';
import merge from './util/merge';

/*
options for isURL method

require_protocol - if set as true isURL will return false if protocol is not present in the URL
require_valid_protocol - isURL will check if the URL's protocol is present in the protocols option
protocols - valid protocols can be modified with this option
require_host - if set as false isURL will not check if host is present in the URL
require_port - if set as true isURL will check if port is present in the URL
allow_protocol_relative_urls - if set as true protocol relative URLs will be allowed
validate_length - if set as false isURL will skip string length validation (IE maximum is 2083)

*/


const default_url_options = {
  protocols: ['http', 'https', 'ftp'],
  require_tld: true,
  require_protocol: false,
  require_host: true,
  require_port: false,
  require_valid_protocol: true,
  allow_underscores: false,
  allow_trailing_dot: false,
  allow_protocol_relative_urls: false,
  allow_fragments: true,
  allow_query_components: true,
  validate_length: true,
};

const wrapped_ipv6 = /^\[([^\]]+)\](?::([0-9]+))?$/;

function isRegExp(obj) {
  return Object.prototype.toString.call(obj) === '[object RegExp]';
}

function checkHost(host, matches) {
  for (let i = 0; i < matches.length; i++) {
    let match = matches[i];
    if (host === match || (isRegExp(match) && match.test(host))) {
      return true;
    }
  }
  return false;
}

export default function isURL(url, options) {
  assertString(url);
  if (!url || /[\s<>]/.test(url)) {
    return false;
  }
  if (url.indexOf('mailto:') === 0) {
    return false;
  }
  options = merge(options, default_url_options);

  if (options.validate_length && url.length >= 2083) {
    return false;
  }

  if (!options.allow_fragments && url.includes('#')) {
    return false;
  }

  if (!options.allow_query_components && (url.includes('?') || url.includes('&'))) {
    return false;
  }

  let protocol, auth, host, hostname, port, port_str, split, ipv6;

  split = url.split('#');
  url = split.shift();

  split = url.split('?');
  url = split.shift();

  // Replaced the 'split("://")' logic with a regex to match the protocol.
  // This correctly identifies schemes like `javascript:` which don't use `//`.
  // However, we need to be careful not to confuse authentication credentials (user:password@host)
  // with protocols. A colon before an @ symbol might be part of auth, not a protocol separator.
  const protocol_match = url.match(/^([a-z][a-z0-9+\-.]*):/i);
  let had_explicit_protocol = false;

  const cleanUpProtocol = (potential_protocol) => {
    had_explicit_protocol = true;
    protocol = potential_protocol.toLowerCase();

    if (options.require_valid_protocol && options.protocols.indexOf(protocol) === -1) {
      // The identified protocol is not in the allowed list.
      return false;
    }

    // Remove the protocol from the URL string.
    return url.substring(protocol_match[0].length);
  };

  if (protocol_match) {
    const potential_protocol = protocol_match[1];
    const after_colon = url.substring(protocol_match[0].length);

    // Check if what follows looks like authentication credentials (user:password@host)
    // rather than a protocol. This happens when:
    // 1. There's no `//` after the colon (protocols like `http://` have this)
    // 2. There's an `@` symbol before any `/`
    // 3. The part before `@` contains only valid auth characters (alphanumeric, -, _, ., %, :)
    const starts_with_slashes = after_colon.slice(0, 2) === '//';

    if (!starts_with_slashes) {
      const first_slash_position = after_colon.indexOf('/');
      const before_slash = first_slash_position === -1
        ? after_colon
        : after_colon.substring(0, first_slash_position);
      const at_position = before_slash.indexOf('@');

      if (at_position !== -1) {
        const before_at = before_slash.substring(0, at_position);
        const valid_auth_regex = /^[a-zA-Z0-9\-_.%:]*$/;
        const is_valid_auth = valid_auth_regex.test(before_at);

        if (is_valid_auth) {
          // This looks like authentication (e.g., user:password@host), not a protocol
          if (options.require_protocol) {
            return false;
          }

          // Don't consume the colon; let the auth parsing handle it later
        } else {
          // This looks like a malicious protocol (e.g., javascript:alert();@host)
          url = cleanUpProtocol(potential_protocol);

          if (url === false) {
            return false;
          }
        }
      } else {
        // No @ symbol, this is definitely a protocol
        url = cleanUpProtocol(potential_protocol);

        if (url === false) {
          return false;
        }
      }
    } else {
      // Starts with '//', this is definitely a protocol like http://
      url = cleanUpProtocol(potential_protocol);

      if (url === false) {
        return false;
      }
    }
  } else if (options.require_protocol) {
    return false;
  }

  // Handle leading '//' only as protocol-relative when there was NO explicit protocol.
  // If there was an explicit protocol, '//' is the normal separator
  // and should be stripped unconditionally.
  if (url.slice(0, 2) === '//') {
    if (!had_explicit_protocol && !options.allow_protocol_relative_urls) {
      return false;
    }

    url = url.slice(2);
  }

  if (url === '') {
    return false;
  }

  split = url.split('/');
  url = split.shift();

  if (url === '' && !options.require_host) {
    return true;
  }

  split = url.split('@');
  if (split.length > 1) {
    if (options.disallow_auth) {
      return false;
    }
    if (split[0] === '') {
      return false;
    }
    auth = split.shift();
    if (auth.indexOf(':') >= 0 && auth.split(':').length > 2) {
      return false;
    }
    const [user, password] = auth.split(':');
    if (user === '' && password === '') {
      return false;
    }
  }
  hostname = split.join('@');

  port_str = null;
  ipv6 = null;
  const ipv6_match = hostname.match(wrapped_ipv6);
  if (ipv6_match) {
    host = '';
    ipv6 = ipv6_match[1];
    port_str = ipv6_match[2] || null;
  } else {
    split = hostname.split(':');
    host = split.shift();
    if (split.length) {
      port_str = split.join(':');
    }
  }

  if (port_str !== null && port_str.length > 0) {
    port = parseInt(port_str, 10);
    if (!/^[0-9]+$/.test(port_str) || port <= 0 || port > 65535) {
      return false;
    }
  } else if (options.require_port) {
    return false;
  }

  if (options.host_whitelist) {
    return checkHost(host, options.host_whitelist);
  }

  if (host === '' && !options.require_host) {
    return true;
  }

  if (!isIP(host) && !isFQDN(host, options) && (!ipv6 || !isIP(ipv6, 6))) {
    return false;
  }

  host = host || ipv6;

  if (options.host_blacklist && checkHost(host, options.host_blacklist)) {
    return false;
  }

  return true;
}
