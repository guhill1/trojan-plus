/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2017-2020  The Trojan Authors.
 * Copyright (C) 2020 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <boost/property_tree/json_parser.hpp>
#include <cstdlib>
#include <gsl/gsl>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#include <tchar.h>
#include <wincrypt.h>
#endif // _WIN32
#ifdef __APPLE__
#include <Security/Security.h>
#endif // __APPLE__

#include "core/icmpd.h"
#include "core/utils.h"
#include "session/session.h"
#include "ssl/ssldefaults.h"
#include "ssl/sslsession.h"

using namespace std;
using namespace boost::property_tree;
using namespace boost::asio::ssl;

const static int default_udp_timeout            = 60;
const static int default_udp_forward_socket_buf = 65536 * 20;
const static int default_udp_socket_buf         = -1; // -1 means don't setsocketopt
const static int default_udp_recv_buf           = 8192;

const static int default_log_level = int(Log::INFO);

const static long default_ssl_session_timeout   = 600;
const static int default_ssl_shutdown_wait_time = 30;

const static int default_tcp_fast_open_qlen   = 20;
const static int default_tcp_connect_time_out = 10;

const static uint16_t default_mysql_server_port = 3306;

const static uint32_t default_experimental_pipeline_num        = 0;
const static uint32_t default_experimental_pipeline_ack_window = 200;

const static uint16_t default_tun_mtu = 1500;
const static int default_tun_fd       = -1;

const static uint16_t default_dns_port      = 53;
const static int default_dns_udp_timeout    = 5;
const static int default_dns_udp_recv_buf   = 512 * 4;
const static int default_dns_udp_socket_buf = -1;

void Config::load(const string& filename) {
    _guard;
    ptree tree;
    read_json(filename, tree);
    populate(tree);
    _unguard;
}

void Config::populate(const string& JSON) {
    _guard;
    istringstream s(JSON);
    ptree tree;
    read_json(s, tree);
    populate(tree);
    _unguard;
}

void Config::populate(const ptree& tree) {
    _guard;
    // read the log_level first
    log_level = static_cast<Log::Level>(tree.get("log_level", default_log_level));
    if (Log::level == Log::INVALID) {
        // don't let load-balance config override the log level
        Log::level = log_level;
    }

    string rt = tree.get("run_type", string("client"));
    if (rt == "server") {
        run_type = SERVER;
    } else if (rt == "forward") {
        run_type = FORWARD;
    } else if (rt == "nat") {
        run_type = NAT;
    } else if (rt == "client") {
        run_type = CLIENT;
    } else if (rt == "client_tun") {
        run_type = CLIENT_TUN;
    } else if (rt == "server_tun") {
        run_type = SERVERT_TUN;
    } else {
        throw runtime_error("wrong run_type in config file");
    }
    local_addr  = tree.get("local_addr", string());
    local_port  = tree.get("local_port", uint16_t());
    remote_addr = tree.get("remote_addr", string());
    remote_port = tree.get("remote_port", uint16_t());
    target_addr = tree.get("target_addr", string());
    target_port = tree.get("target_port", uint16_t());
    map<string, string>().swap(password);
    if (tree.get_child_optional("password")) {
        for (const auto& item : tree.get_child("password")) {
            const auto& p       = item.second.get_value<string>();
            password[SHA224(p)] = p;
        }
    }

    udp_timeout            = tree.get("udp_timeout", default_udp_timeout);
    udp_socket_buf         = tree.get("udp_socket_buf", default_udp_socket_buf);
    udp_forward_socket_buf = tree.get("udp_forward_socket_buf", default_udp_forward_socket_buf);
    udp_recv_buf           = tree.get("udp_recv_buf", default_udp_recv_buf);

    ssl.verify               = tree.get("ssl.verify", true);
    ssl.verify_hostname      = tree.get("ssl.verify_hostname", true);
    ssl.cert                 = tree.get("ssl.cert", string());
    ssl.key                  = tree.get("ssl.key", string());
    ssl.key_password         = tree.get("ssl.key_password", string());
    ssl.cipher               = tree.get("ssl.cipher", string());
    ssl.cipher_tls13         = tree.get("ssl.cipher_tls13", string());
    ssl.prefer_server_cipher = tree.get("ssl.prefer_server_cipher", true);
    ssl.sni                  = tree.get("ssl.sni", string());
    ssl.alpn                 = string();
    if (tree.get_child_optional("ssl.alpn")) {
        for (const auto& item : tree.get_child("ssl.alpn")) {
            const auto& proto = item.second.get_value<string>();
            ssl.alpn += (char)((unsigned char)(proto.length()));
            ssl.alpn += proto;
        }
    }
    map<string, uint16_t>().swap(ssl.alpn_port_override);
    if (tree.get_child_optional("ssl.alpn_port_override")) {
        for (const auto& item : tree.get_child("ssl.alpn_port_override")) {
            ssl.alpn_port_override[item.first] = item.second.get_value<uint16_t>();
        }
    }
    ssl.reuse_session          = tree.get("ssl.reuse_session", true);
    ssl.session_ticket         = tree.get("ssl.session_ticket", false);
    ssl.session_timeout        = tree.get("ssl.session_timeout", default_ssl_session_timeout);
    ssl.ssl_shutdown_wait_time = tree.get("ssl.ssl_shutdown_wait_time", default_ssl_shutdown_wait_time);
    ssl.plain_http_response    = tree.get("ssl.plain_http_response", string());
    ssl.curves                 = tree.get("ssl.curves", string());
    ssl.dhparam                = tree.get("ssl.dhparam", string());

    tcp.prefer_ipv4      = tree.get("tcp.prefer_ipv4", false);
    tcp.no_delay         = tree.get("tcp.no_delay", true);
    tcp.keep_alive       = tree.get("tcp.keep_alive", true);
    tcp.reuse_port       = tree.get("tcp.reuse_port", false);
    tcp.fast_open        = tree.get("tcp.fast_open", false);
    tcp.use_tproxy       = tree.get("tcp.use_tproxy", false);
    tcp.fast_open_qlen   = tree.get("tcp.fast_open_qlen", default_tcp_fast_open_qlen);
    tcp.connect_time_out = tree.get("tcp.connect_time_out", default_tcp_connect_time_out);

    mysql.enabled     = tree.get("mysql.enabled", false);
    mysql.server_addr = tree.get("mysql.server_addr", string("127.0.0.1"));
    mysql.server_port = tree.get("mysql.server_port", default_mysql_server_port);
    mysql.database    = tree.get("mysql.database", string("trojan"));
    mysql.username    = tree.get("mysql.username", string("trojan"));
    mysql.password    = tree.get("mysql.password", string());
    mysql.cafile      = tree.get("mysql.cafile", string());

    experimental.pipeline_num = tree.get("experimental.pipeline_num", default_experimental_pipeline_num);
    experimental.pipeline_ack_window =
      tree.get("experimental.pipeline_ack_window", default_experimental_pipeline_ack_window);
    experimental.pipeline_loadbalance_configs.clear();
    experimental._pipeline_loadbalance_configs.clear();
    experimental._pipeline_loadbalance_context.clear();
    experimental.pipeline_proxy_icmp = tree.get("experimental.pipeline_proxy_icmp", false);
    if (run_type != SERVER) {
        if (tree.get_child_optional("experimental.pipeline_loadbalance_configs")) {
            for (const auto& item : tree.get_child("experimental.pipeline_loadbalance_configs")) {
                const auto& config = item.second.get_value<string>();
                experimental.pipeline_loadbalance_configs.emplace_back(config);
            }

            if (!experimental.pipeline_loadbalance_configs.empty()) {
                std::string tmp;
                _log_with_date_time("Pipeline will use load balance config:", Log::WARN);
                for (const auto& item : experimental.pipeline_loadbalance_configs) {

                    auto other = make_shared<Config>();
                    other->load(item);

                    auto ssl = make_shared<boost::asio::ssl::context>(context::sslv23);
                    other->prepare_ssl_context(*ssl, tmp);

                    experimental._pipeline_loadbalance_configs.emplace_back(other);
                    experimental._pipeline_loadbalance_context.emplace_back(ssl);
                    _log_with_date_time("Loaded " + item + " config.", Log::WARN);
                }

                if (experimental.pipeline_num == 0) {
                    _log_with_date_time(
                      "Pipeline load balance need to enable pipeline (set pipeline_num as non zero)", Log::ERROR);
                }
            }
        }
    }

    tun.tun_name       = tree.get("tun.tun_name", string());
    tun.net_ip         = tree.get("tun.net_ip", string());
    tun.net_mask       = tree.get("tun.net_mask", string());
    tun.mtu            = tree.get("tun.mtu", default_tun_mtu);
    tun.tun_fd         = tree.get("tun.tun_fd", default_tun_fd);
    tun.redirect_local = tree.get("tun.redirect_local", false);

    dns.enabled          = tree.get("dns.enabled", false);
    dns.port             = tree.get("dns.port", default_dns_port);
    dns.udp_timeout      = tree.get("dns.dns_udp_timeout", default_dns_udp_timeout);
    dns.udp_recv_buf     = tree.get("dns.udp_recv_buf", default_dns_udp_recv_buf);
    dns.udp_socket_buf   = tree.get("dns.udp_socket_buf", default_dns_udp_socket_buf);
    dns.gfwlist          = tree.get("dns.gfwlist", string());
    dns.enable_cached    = tree.get("dns.enable_cached", false);
    dns.enable_ping_test = tree.get("dns.enable_ping_test", false);

    load_dns(tree);

    route.enabled              = tree.get("route.enabled", false);
    route.proxy_type           = (RouteType)tree.get("route.proxy_type", (int)RouteType::route_all);
    route.cn_mainland_ips_file = tree.get("route.cn_mainland_ips_file", string());
    route.white_ips            = tree.get("route.white_ips", string());
    route.proxy_ips            = tree.get("route.proxy_ips", string());

    if (route.enabled) {
        if (run_type == CLIENT_TUN) {
            size_t count = 0;
            route._cn_mainland_ips_matcher.load_from_file(route.cn_mainland_ips_file, count);
            _log_with_date_time(
              "[route] load " + to_string(count) + " cn_mainland_ips from file " + route.cn_mainland_ips_file);

            route._white_ips_matcher.load_from_file(route.white_ips, count);
            _log_with_date_time("[route] load " + to_string(count) + " white_ips from file " + route.white_ips);

            route._proxy_ips_matcher.load_from_file(route.proxy_ips, count);
            _log_with_date_time("[route] load " + to_string(count) + " proxy_ips from file " + route.proxy_ips);

            if (route.proxy_type == RouteType::route_gfwlist && !dns.enabled) {
                _log_with_date_time("[route] route_gfwlist need dns with gfw's list support!", Log::ERROR);
            }

            _log_with_date_time("[route] type: " + to_string(route.proxy_type));
        } else {
            _log_with_date_time("[route] Now cannot enable route function without tun mode!", Log::ERROR);
        }
    } else {
        if (run_type == CLIENT_TUN) {
            _log_with_date_time("[tun] tun mode need route's config support!", Log::WARN);
        }
    }

    const auto hash_str = get_remote_addr() + ":" + to_string(get_remote_port());
    compare_hash        = get_hashCode(hash_str);
    _log_with_date_time_ALL("[config] has loaded [" + hash_str + "] in hashCode: " + to_string(compare_hash));

    _unguard;
}

void Config::load_dns(const boost::property_tree::ptree& tree) {
    _guard;

    if (!dns.enabled) {
        return;
    }
    if (!dns.gfwlist.empty()) {
        size_t count = 0;
        if (dns._gfwlist_matcher.load_from_file(dns.gfwlist, count)) {
            if (count == 0) {
                dns.enabled = false;
                _log_with_date_time("[dns] '" + dns.gfwlist + "' is empty!", Log::ERROR);
            } else {
                _log_with_date_time("[dns] loaded " + to_string(count) + " domains from " + dns.gfwlist, Log::WARN);
            }
        } else {
            dns.enabled = false;
            _log_with_date_time("[dns] cannot open '" + dns.gfwlist + "' file to read!", Log::ERROR);
        }
    } else {
        dns.enabled = false;
        _log_with_date_time("[dns] please fill 'tun.gfwlist' as filename!", Log::ERROR);
    }

    if (dns.enabled) {
        if (tree.get_child_optional("dns.up_dns_server")) {
            for (const auto& item : tree.get_child("dns.up_dns_server")) {
                dns.up_dns_server.emplace_back(item.second.get_value<string>());
            }
        }

        if (dns.up_dns_server.empty()) {
            _log_with_date_time("[dns] up_dns_server is empty, filled by default up stream server!", Log::WARN);
            dns.up_dns_server.emplace_back("119.29.29.29");
            dns.up_dns_server.emplace_back("223.5.5.5");
        }

        if (tree.get_child_optional("dns.up_gfw_dns_server")) {
            for (const auto& item : tree.get_child("dns.up_gfw_dns_server")) {
                dns.up_gfw_dns_server.emplace_back(item.second.get_value<string>());
            }
        }

        if (dns.up_gfw_dns_server.empty()) {
            _log_with_date_time("[dns] up_gfw_dns_server is empty, filled by default up stream server!", Log::WARN);
            dns.up_gfw_dns_server.emplace_back("8.8.8.8");
        }
    }
    _unguard;
}

bool Config::try_prepare_pipeline_proxy_icmp(bool is_ipv4) {
    _guard;
    if (experimental.pipeline_proxy_icmp) {
        // set this icmp false first
        experimental.pipeline_proxy_icmp = false;

        if (!is_ipv4) {
            _log_with_date_time("Pipeline proxy icmp can only run in ipv4", Log::ERROR);
            return false;
        }

        if (get_experimental().pipeline_num == 0) {
            _log_with_date_time(
              "Pipeline proxy ICMP message need to enable pipeline (set pipeline_num as non zero)", Log::ERROR);
            return false;
        }

        if (get_run_type() != Config::SERVER) {
            if (get_run_type() != Config::NAT) {
                _log_with_date_time("Pipeline proxy icmp can only run in NAT & SERVER type", Log::ERROR);
                return false;
            }

            if (!icmpd::get_icmpd_lock()) {
                _log_with_date_time("Pipeline proxy icmp disabled in this process, cannot get lock, it can only run in "
                                    "one process of host",
                  Log::WARN);
                return false;
            }
        }

        experimental.pipeline_proxy_icmp = true;
        return true;
    }

    return false;
    _unguard;
}

bool Config::sip003() {
    _guard;
    char* JSON = getenv("SS_PLUGIN_OPTIONS");
    if (JSON == nullptr) {
        return false;
    }
    populate(JSON);
    switch (run_type) {
        case SERVER:
            local_addr = getenv("SS_REMOTE_HOST");
            local_port = atoi(getenv("SS_REMOTE_PORT"));
            break;
        case CLIENT:
        case NAT:
        case CLIENT_TUN:
        case SERVERT_TUN:
            throw runtime_error("SIP003 with wrong run_type");
        case FORWARD:
            remote_addr = getenv("SS_REMOTE_HOST");
            remote_port = atoi(getenv("SS_REMOTE_PORT"));
            local_addr  = getenv("SS_LOCAL_HOST");
            local_port  = atoi(getenv("SS_LOCAL_PORT"));
            break;
    }
    return true;
    _unguard;
}

void Config::prepare_ssl_context(boost::asio::ssl::context& ssl_context, string& plain_http_response) {
    _guard;
    auto* native_context = ssl_context.native_handle();
    ssl_context.set_options(
      context::default_workarounds | context::no_sslv2 | context::no_sslv3 | context::single_dh_use);
    if (!ssl.curves.empty()) {
        SSL_CTX_set1_curves_list(native_context, ssl.curves.c_str());
    }
    if (run_type == Config::SERVER) {
        ssl_context.use_certificate_chain_file(ssl.cert);
        ssl_context.set_password_callback(
          [this](size_t, context_base::password_purpose) { return this->ssl.key_password; });
        ssl_context.use_private_key_file(ssl.key, context::pem);
        if (ssl.prefer_server_cipher) {
            SSL_CTX_set_options(native_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
        if (!ssl.alpn.empty()) {
            SSL_CTX_set_alpn_select_cb(
              native_context,
              [](SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen,
                void* config) -> int {
                  _guard;
                  if (SSL_select_next_proto((unsigned char**)out, outlen,
                        (unsigned char*)(((Config*)config)->ssl.alpn.c_str()),
                        (unsigned int)((Config*)config)->ssl.alpn.length(), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                      return SSL_TLSEXT_ERR_NOACK;
                  }
                  return SSL_TLSEXT_ERR_OK;
                  _unguard;
              },
              this);
        }
        if (ssl.reuse_session) {
            SSL_CTX_set_timeout(native_context, ssl.session_timeout);
            if (!ssl.session_ticket) {
                SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
            }
        } else {
            SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_OFF);
            SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
        }

        if (!ssl.plain_http_response.empty()) {
            ifstream ifs(ssl.plain_http_response, ios::binary);
            if (!ifs.is_open()) {
                throw runtime_error(ssl.plain_http_response + ": " + strerror(errno));
            }
            plain_http_response = string(istreambuf_iterator<char>(ifs), istreambuf_iterator<char>());
        }
        if (ssl.dhparam.empty()) {
            ssl_context.use_tmp_dh(
              boost::asio::const_buffer((const void*)SSLDefaults::g_dh2048_sz, SSLDefaults::g_dh2048_sz_size));
        } else {
            ssl_context.use_tmp_dh_file(ssl.dhparam);
        }

    } else {
        if (ssl.sni.empty()) {
            ssl.sni = remote_addr;
        }
        if (ssl.verify) {
            ssl_context.set_verify_mode(verify_peer);
            if (ssl.cert.empty()) {
                ssl_context.set_default_verify_paths();
#ifdef _WIN32
                HCERTSTORE h_store = CertOpenSystemStore(0, _T("ROOT"));
                if (h_store) {
                    X509_STORE* store        = SSL_CTX_get_cert_store(native_context);
                    PCCERT_CONTEXT p_context = nullptr;
                    while ((p_context = CertEnumCertificatesInStore(h_store, p_context))) {
                        const unsigned char* encoded_cert = p_context->pbCertEncoded;
                        X509* x509                        = d2i_X509(nullptr, &encoded_cert, p_context->cbCertEncoded);
                        if (x509) {
                            X509_STORE_add_cert(store, x509);
                            X509_free(x509);
                        }
                    }
                    CertCloseStore(h_store, 0);
                }
#endif // _WIN32
#ifdef __APPLE__

                SecKeychainRef systemRoots = nullptr;
                auto status =
                  SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &systemRoots);
                if (status == noErr) {
                    CFArrayRef currentSearchList = nullptr;
                    status                       = SecKeychainCopySearchList(&currentSearchList);
                    if (status == noErr) {

                        const CFIndex Capacity = 5;
                        CFMutableArrayRef newSearchList =
                          CFArrayCreateMutableCopy(nullptr, Capacity, currentSearchList);
                        CFRelease(currentSearchList);

                        CFArrayAppendValue(newSearchList, systemRoots);

                        CFMutableDictionaryRef dictRef = CFDictionaryCreateMutable(
                          nullptr, Capacity, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

                        CFDictionaryAddValue(dictRef, kSecClass, kSecClassCertificate);
                        CFDictionaryAddValue(dictRef, kSecMatchLimit, kSecMatchLimitAll);
                        CFDictionaryAddValue(dictRef, kSecReturnRef, kCFBooleanTrue);
                        CFDictionaryAddValue(dictRef, kSecMatchSearchList, newSearchList);

                        CFArrayRef result = nullptr;
                        status            = SecItemCopyMatching(dictRef, (CFTypeRef*)&result);
                        if (status == noErr) {
                            auto* store         = SSL_CTX_get_cert_store(native_context);
                            const CFIndex count = CFArrayGetCount(result);
                            for (int i = 0; i < count; i++) {
                                auto* item = (SecKeychainItemRef)CFArrayGetValueAtIndex(result, i);

                                void* certData    = nullptr;
                                UInt32 certLength = 0;
                                status            = SecKeychainItemCopyAttributesAndData(
                                  item, nullptr, nullptr, nullptr, &certLength, &certData);

                                if (status == noErr && certData != nullptr) {
                                    /*required because d2i_X509 is modifying pointer */
                                    auto* ptr  = static_cast<unsigned char*>(certData);
                                    auto* cert = d2i_X509(nullptr, (const unsigned char**)&ptr, certLength);
                                    if (cert == nullptr) {
                                        SecKeychainItemFreeAttributesAndData(nullptr, certData);
                                        continue;
                                    }
                                    if (X509_STORE_add_cert(store, cert) == 0) {
                                        _log_with_date_time(
                                          " X509_STORE_add_cert add cert failed, cert length: " + to_string(certLength),
                                          Log::WARN);
                                    }
                                    X509_free(cert);
                                    SecKeychainItemFreeAttributesAndData(nullptr, certData);
                                }
                            }
                            CFRelease(result);
                        }

                        CFRelease(dictRef);
                        CFRelease(newSearchList);
                    }
                    CFRelease(systemRoots);
                }
#endif // __APPLE__
            } else {
                ssl_context.load_verify_file(ssl.cert);
            }
            if (ssl.verify_hostname) {
#if BOOST_VERSION >= 107300
                ssl_context.set_verify_callback(host_name_verification(ssl.sni));
#else
                ssl_context.set_verify_callback(rfc2818_verification(ssl.sni));
#endif
            }
            X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
            SSL_CTX_set1_param(native_context, param);
            X509_VERIFY_PARAM_free(param);
        } else {
            ssl_context.set_verify_mode(verify_none);
        }
        if (!ssl.alpn.empty()) {
            SSL_CTX_set_alpn_protos(
              native_context, (unsigned char*)(ssl.alpn.c_str()), (unsigned int)ssl.alpn.length());
        }
        if (ssl.reuse_session) {
            SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_CLIENT);
            SSLSession::set_callback(native_context);
            if (!ssl.session_ticket) {
                SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
            }
        } else {
            SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
        }
    }

    if (!ssl.cipher.empty()) {
        SSL_CTX_set_cipher_list(native_context, ssl.cipher.c_str());
    }

    if (!ssl.cipher_tls13.empty()) {
#ifdef ENABLE_TLS13_CIPHERSUITES
        SSL_CTX_set_ciphersuites(native_context, ssl.cipher_tls13.c_str());
#else  // ENABLE_TLS13_CIPHERSUITES
        _log_with_date_time("TLS1.3 ciphersuites are not supported", Log::WARN);
#endif // ENABLE_TLS13_CIPHERSUITES
    }

    if (Log::keylog != nullptr) {
#ifdef ENABLE_SSL_KEYLOG
        SSL_CTX_set_keylog_callback(native_context, [](const SSL*, const char* line) {
            fprintf(Log::keylog, "%s\n", line);
            fflush(Log::keylog);
        });
#else  // ENABLE_SSL_KEYLOG
        _log_with_date_time("SSL KeyLog is not supported", Log::WARN);
#endif // ENABLE_SSL_KEYLOG
    }

    _unguard;
}

void Config::prepare_ssl_reuse(SSLSocket& socket) const {
    _guard;
    auto* ssl_handle = socket.native_handle();
    if (!ssl.sni.empty()) {
        SSL_set_tlsext_host_name(ssl_handle, ssl.sni.c_str());
    }
    if (ssl.reuse_session) {
        auto* session = SSLSession::get_session();
        if (session != nullptr) {
            SSL_set_session(ssl_handle, session);
        }
    }
    _unguard;
}

string Config::SHA224(const string& message) {
    _guard;

    uint8_t digest[EVP_MAX_MD_SIZE];
    char mdString[MAX_PASSWORD_LENGTH + 1];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx         = nullptr;
    if ((ctx = EVP_MD_CTX_new()) == nullptr) {
        throw runtime_error("[sha224] could not create hash context");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr) == 0) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[sha224] could not initialize hash context");
    }
    if (EVP_DigestUpdate(ctx, message.c_str(), message.length()) == 0) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[sha224] could not update hash");
    }
    if (EVP_DigestFinal_ex(ctx, (unsigned char*)digest, &digest_len) == 0) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[sha224] could not output hash");
    }

    if (digest_len * 2 >= MAX_PASSWORD_LENGTH) {
        throw runtime_error("[sha224] password length is too large");
    }

    for (unsigned int i = 0; i < digest_len; ++i) {
        sprintf((mdString + (i << 1)), "%02x", (unsigned int)digest[i]);
    }
    gsl::at(mdString, digest_len << 1) = '\0';
    EVP_MD_CTX_free(ctx);
    return string((const char*)mdString);

    _unguard;
}
