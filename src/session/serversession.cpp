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

#include "serversession.h"

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(Service* _service, const Config& config, boost::asio::ssl::context& ssl_context,
  shared_ptr<Authenticator> auth, const std::string& plain_http_response)
    : SocketSession(_service, config),
      status(HANDSHAKE),
      out_socket(_service->get_io_context()),
      udp_socket(_service->get_io_context()),
      udp_resolver(_service->get_io_context()),
      auth(move(auth)),
      plain_http_response(plain_http_response),
      has_queried_out(false) {

    set_session_name("ServerSession");
    in_socket = make_shared<SSLSocket>(_service->get_io_context(), ssl_context);
}

ServerSession::ServerSession(Service* _service, const Config& config, shared_ptr<SSLSocket> socket,
  std::shared_ptr<Authenticator> auth, const std::string& plain_http_response)
    : SocketSession(_service, config),
      status(HANDSHAKE),
      in_socket(move(socket)),
      out_socket(_service->get_io_context()),
      udp_socket(_service->get_io_context()),
      udp_resolver(_service->get_io_context()),
      auth(move(auth)),
      plain_http_response(plain_http_response),
      has_queried_out(false) {

    boost::system::error_code ec;
    set_in_endpoint(in_socket->next_layer().remote_endpoint(ec));
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }
}

tcp::socket& ServerSession::accept_socket() { return (tcp::socket&)in_socket->next_layer(); }

void ServerSession::start() {

    if (!get_pipeline_component().is_using_pipeline()) {
        boost::system::error_code ec;
        set_in_endpoint(in_socket->next_layer().remote_endpoint(ec));
        if (ec) {
            output_debug_info_ec(ec);
            destroy();
            return;
        }
        auto self = shared_from_this();
        in_socket->async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
            if (error) {
                _log_with_endpoint(get_in_endpoint(), "SSL handshake failed: " + error.message(), Log::ERROR);
                if (error.message() == "http request" && plain_http_response.empty()) {
                    get_stat().inc_recv_len(plain_http_response.length());
                    boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response),
                      [this, self](const boost::system::error_code, size_t) {
                          output_debug_info();
                          destroy();
                      });
                    return;
                }
                output_debug_info();
                destroy();
                return;
            }
            in_async_read();
        });
    } else {
        in_async_read();
    }
}

void ServerSession::in_async_read() {
    if (get_pipeline_component().is_using_pipeline()) {
        get_pipeline_component().get_pipeline_data_cache().async_read(
          [this](const string_view& data, size_t ack_count) { in_recv(data, ack_count); });
    } else {
        in_read_buf.begin_read(__FILE__, __LINE__);
        in_read_buf.consume_all();
        auto self = shared_from_this();
        in_socket->async_read_some(
          in_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
              in_read_buf.end_read();
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              in_read_buf.commit(length);
              in_recv(in_read_buf);
          });
    }
}

void ServerSession::in_async_write(const string_view& data) {
    _log_with_date_time_DEBUG("ServerSession::in_async_write session_id: " + to_string(get_session_id()) +
                              " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_in_async_write", data);
    auto self = shared_from_this();
    if (get_pipeline_component().is_using_pipeline()) {
        if (!pipeline_session.expired()) {
            (dynamic_cast<PipelineSession*>(pipeline_session.lock().get()))
              ->session_write_data(*this, data, [this, self](const boost::system::error_code ec) {
                  if (ec) {
                      output_debug_info_ec(ec);
                      destroy();
                      return;
                  }
                  in_sent();
              });
        } else {
            output_debug_info();
            destroy();
        }
    } else {
        auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
        boost::asio::async_write(
          *in_socket, data_copy->data(), [this, self, data_copy](const boost::system::error_code error, size_t) {
              get_service()->get_sending_data_allocator().free(data_copy);
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              in_sent();
          });
    }
}

void ServerSession::out_async_read() {
    if (get_pipeline_component().is_using_pipeline()) {
        if (!get_pipeline_component().pre_call_ack_func()) {
            _log_with_endpoint_DEBUG(get_in_endpoint(), "session_id: " + to_string(get_session_id()) +
                                                          " cannot ServerSession::out_async_read ! Is waiting for ack");
            return;
        }
        _log_with_endpoint_DEBUG(get_in_endpoint(), "session_id: " + to_string(get_session_id()) +
                                                      " permit to ServerSession::out_async_read aysnc! ack:" +
                                                      to_string(get_pipeline_component().pipeline_ack_counter));
    }

    out_read_buf.begin_read(__FILE__, __LINE__);
    out_read_buf.consume_all();
    auto self = shared_from_this();
    out_socket.async_read_some(
      out_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
          out_read_buf.end_read();
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          out_read_buf.commit(length);
          out_recv(out_read_buf);
      });
}

void ServerSession::out_async_write(const string_view& data, size_t ack_count) {
    _log_with_date_time_DEBUG("ServerSession::out_async_write session_id: " + to_string(get_session_id()) +
                              " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_out_async_write", data);

    if (get_pipeline_component().is_using_pipeline() && !pipeline_session.expired()) {
        get_pipeline_component().set_async_writing_data(true);
    }

    auto self      = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    boost::asio::async_write(
      out_socket, data_copy->data(), [this, self, data_copy, ack_count](const boost::system::error_code error, size_t) {
          get_service()->get_sending_data_allocator().free(data_copy);
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }

          if (get_pipeline_component().is_using_pipeline() && !pipeline_session.expired()) {

              if (get_pipeline_component().is_write_close_future() &&
                  !get_pipeline_component().get_pipeline_data_cache().has_queued_data()) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }

              get_pipeline_component().set_async_writing_data(false);

              (dynamic_cast<PipelineSession*>(pipeline_session.lock().get()))
                ->session_write_ack(
                  *this,
                  [this, self](const boost::system::error_code ec) {
                      if (ec) {
                          output_debug_info_ec(ec);
                          destroy();
                          return;
                      }
                      out_sent();
                  },
                  ack_count);
          } else {
              out_sent();
          }
      });
}

void ServerSession::out_udp_async_read() {
    udp_read_buf.begin_read(__FILE__, __LINE__);
    udp_read_buf.consume_all();
    auto self = shared_from_this();
    udp_socket.async_receive_from(udp_read_buf.prepare(get_config().get_udp_recv_buf()), out_udp_endpoint,
      [this, self](const boost::system::error_code error, size_t length) {
          udp_read_buf.end_read();
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          udp_read_buf.commit(length);
          out_udp_recv(udp_read_buf, out_udp_endpoint);
      });
}

void ServerSession::out_udp_async_write(const string_view& data, const udp::endpoint& endpoint) {
    auto self      = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    udp_socket.async_send_to(
      data_copy->data(), endpoint, [this, self, data_copy](const boost::system::error_code error, size_t) {
          get_service()->get_sending_data_allocator().free(data_copy);
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          out_udp_sent();
      });
}

void ServerSession::in_recv(const string_view& data, size_t ack_count) {
    _log_with_date_time_DEBUG("ServerSession::in_recv session_id: " + to_string(get_session_id()) +
                              " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_in_recv", data);
    if (status == HANDSHAKE) {

        if (has_queried_out) {
            // pipeline session will call this in_recv directly so that the HANDSHAKE status will remain for a while
            streambuf_append(out_write_buf, data);
            get_stat().inc_sent_len(data.length());
            return;
        }

        TrojanRequest req;
        bool use_alpn = req.parse(data) == -1;
        if (!use_alpn) {
            auto password_iterator = get_config().get_password().find(req.password);
            if (password_iterator == get_config().get_password().end()) {
                if (auth && auth->auth(req.password)) {
                    auth_password = req.password;
                    _log_with_endpoint(get_in_endpoint(),
                      "session_id: " + to_string(get_session_id()) + " authenticated by authenticator (" +
                        req.password.substr(0, 7) + ')',
                      Log::INFO);
                } else {
                    use_alpn = true;
                }
            } else {
                _log_with_endpoint(get_in_endpoint(),
                  "session_id: " + to_string(get_session_id()) + " authenticated as " + password_iterator->second,
                  Log::INFO);
            }
        }

        string query_addr = use_alpn ? get_config().get_remote_addr() : req.address.address;
        string query_port = to_string([&]() {
            if (!use_alpn) {
                return req.address.port;
            }
            const unsigned char* alpn_out = nullptr;
            unsigned int alpn_len         = 0;
            SSL_get0_alpn_selected(in_socket->native_handle(), &alpn_out, &alpn_len);
            if (alpn_out == nullptr) {
                return get_config().get_remote_port();
            }
            auto it = get_config().get_ssl().alpn_port_override.find(string((const char*)alpn_out, (size_t)alpn_len));
            return it == get_config().get_ssl().alpn_port_override.end() ? get_config().get_remote_port() : it->second;
        }());

        if (!use_alpn) {
            if (req.command == TrojanRequest::UDP_ASSOCIATE) {
                set_udp_forward_session(true);
                udp_timer_async_wait();

                boost::system::error_code ec;
                udp_associate_endpoint = make_udp_endpoint_safe(req.address.address, req.address.port, ec);
                if (ec) {
                    _log_with_endpoint(udp_associate_endpoint,
                      "session_id: " + to_string(get_session_id()) + " cannot make address for UDP associate to " +
                        req.address.address + ':' + to_string(req.address.port),
                      Log::ERROR);
                    destroy();
                    return;
                }

                _log_with_endpoint(udp_associate_endpoint,
                  "session_id: " + to_string(get_session_id()) + " requested UDP associate to " + req.address.address +
                    ':' + to_string(req.address.port) + " payload length: " + to_string(req.payload.length()),
                  Log::INFO);

                status = UDP_FORWARD;
                udp_data_buf.consume(udp_data_buf.size());
                streambuf_append(udp_data_buf, req.payload);
                out_udp_sent();
                return;
            }

            _log_with_endpoint(get_in_endpoint(),
              "session_id: " + to_string(get_session_id()) + " requested connection to " + req.address.address + ':' +
                to_string(req.address.port),
              Log::INFO);

            streambuf_append(out_write_buf, req.payload);

        } else {
            streambuf_append(out_write_buf, data);
        }

        get_stat().inc_sent_len(out_write_buf.size());
        has_queried_out = true;

        auto self = shared_from_this();
        connect_out_socket(this, query_addr, query_port, get_resolver(), out_socket, get_in_endpoint(), [this, self]() {
            status = FORWARD;
            out_async_read();
            if (out_write_buf.size() != 0) {
                out_async_write(streambuf_to_string_view(out_write_buf));
            } else {
                in_async_read();
            }
        });

    } else if (status == FORWARD) {
        get_stat().inc_sent_len(data.length());
        out_async_write(data, ack_count);
    } else if (status == UDP_FORWARD) {
        streambuf_append(udp_data_buf, data);
        out_udp_sent();
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    } else if (status == UDP_FORWARD) {
        out_udp_async_read();
    }
}

void ServerSession::out_recv(const string_view& data) {
    _log_with_date_time_DEBUG("ServerSession::out_recv session_id: " + to_string(get_session_id()) +
                              " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_out_recv", data);
    if (status == FORWARD) {
        get_stat().inc_recv_len(data.length());
        in_async_write(data);
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void ServerSession::out_udp_recv(const string_view& data, const udp::endpoint& endpoint) {
    if (status == UDP_FORWARD) {
        udp_timer_async_wait();
        size_t length = data.length();
        _log_with_endpoint(udp_associate_endpoint,
          "session_id: " + to_string(get_session_id()) + " received a UDP packet of length " + to_string(length) +
            " bytes from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
        get_stat().inc_recv_len(length);
        out_write_buf.consume(out_write_buf.size());
        in_async_write(streambuf_to_string_view(UDPPacket::generate(out_write_buf, endpoint, data)));
    }
}

void ServerSession::out_udp_sent() {
    if (status == UDP_FORWARD) {
        udp_timer_async_wait();
        if (udp_data_buf.size() == 0) {
            in_async_read();
            return;
        }

        UDPPacket packet;
        size_t packet_len    = 0;
        bool is_packet_valid = packet.parse(streambuf_to_string_view(udp_data_buf), packet_len);
        if (!is_packet_valid) {
            if (udp_data_buf.size() > MAX_BUF_LENGTH) {
                _log_with_endpoint(udp_associate_endpoint,
                  "session_id: " + to_string(get_session_id()) + " UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }

        auto cb = [this](const UDPPacket& packet, size_t packet_len, const udp::endpoint& dst_endpoint) {
            if (!udp_socket.is_open()) {
                auto protocol = dst_endpoint.protocol();
                boost::system::error_code ec;
                udp_socket.open(protocol, ec);
                if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                }
                set_udp_send_recv_buf((int)udp_socket.native_handle(), get_config().get_udp_socket_buf());
                udp_socket.bind(udp::endpoint(protocol, 0), ec);
                if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                }

                _log_with_endpoint(udp_associate_endpoint,
                  "session_id: " + to_string(get_session_id()) + " open UDP socket " +
                    udp_socket.local_endpoint().address().to_string() + ':' +
                    to_string(udp_socket.local_endpoint().port()) + " for relay",
                  Log::INFO);

                out_udp_async_read();
            }

            get_stat().inc_sent_len(packet.length);
            _log_with_endpoint(udp_associate_endpoint, "session_id: " + to_string(get_session_id()) +
                                                         " sent a UDP packet of length " + to_string(packet.length) +
                                                         " bytes to " + packet.address.address + ':' +
                                                         to_string(packet.address.port));

            out_udp_async_write(packet.payload, dst_endpoint);

            // we must consume here after packet.payload has been writen
            udp_data_buf.consume(packet_len);
        };

        if (packet.address.address_type == SOCKS5Address::DOMAINNAME) {

            boost::system::error_code ec;
            auto dst_endpoint = make_udp_endpoint_safe(packet.address.address, packet.address.port, ec);
            if (!ec) {
                cb(packet, packet_len, dst_endpoint);
                return;
            }

            auto payload_tmp_buf = make_shared<string>(packet.payload);
            packet.payload       = *payload_tmp_buf;

            auto self = shared_from_this();
            udp_resolver.async_resolve(packet.address.address, to_string(packet.address.port),
              [this, self, cb, payload_tmp_buf, packet, packet_len](
                const boost::system::error_code error, const udp::resolver::results_type& results) {
                  if (error || results.empty()) {
                      _log_with_endpoint(udp_associate_endpoint,
                        "session_id: " + to_string(get_session_id()) + " cannot resolve remote server hostname " +
                          packet.address.address + ": " + error.message(),
                        Log::ERROR);
                      destroy();
                      return;
                  }

                  auto iterator = results.begin();
                  if (get_config().get_tcp().prefer_ipv4) {
                      for (auto it = results.begin(); it != results.end(); ++it) {
                          const auto& addr = it->endpoint().address();
                          if (addr.is_v4()) {
                              iterator = it;
                              break;
                          }
                      }
                  }

                  auto dst_endpoint =
                    udp::endpoint(make_address(iterator->endpoint().address().to_string()), packet.address.port);

                  _log_with_endpoint(udp_associate_endpoint,
                    "session_id: " + to_string(get_session_id()) + " " + packet.address.address + " is resolved to " +
                      dst_endpoint.address().to_string(),
                    Log::ALL);

                  cb(packet, packet_len, dst_endpoint);
              });
        } else {

            boost::system::error_code ec;
            auto dst_endpoint = make_udp_endpoint_safe(packet.address.address, packet.address.port, ec);
            if (ec) {
                _log_with_endpoint(udp_associate_endpoint,
                  "session_id: " + to_string(get_session_id()) + " cannot make address for UDP destination to " +
                    packet.address.address + ':' + to_string(packet.address.port),
                  Log::ERROR);
                destroy();
                return;
            }

            cb(packet, packet_len, dst_endpoint);
        }
    }
}

void ServerSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;

    _log_with_endpoint(get_in_endpoint(),
      (is_udp_forward_session() ? "[udp] session_id: " : "session_id: ") + to_string(get_session_id()) +
        " disconnected, " + get_stat().to_string(),
      Log::INFO);

    if (auth && !auth_password.empty()) {
        auth->record(auth_password, get_stat().get_recv_len(), get_stat().get_sent_len());
    }
    boost::system::error_code ec;
    get_resolver().cancel();
    udp_resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }

    udp_timer_cancel();
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }

    if (in_socket) {
        shutdown_ssl_socket(this, *in_socket);
    }

    if (!pipeline_call && get_pipeline_component().is_using_pipeline() && !pipeline_session.expired()) {
        (dynamic_cast<PipelineSession*>(pipeline_session.lock().get()))->remove_session_after_destroy(*this);
    }
}
