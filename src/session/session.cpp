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

#include "session.h"
#include "core/service.h"
#include <chrono>
#include <boost/asio/steady_timer.hpp>

using namespace std;
using namespace std::chrono;

constexpr int DEFAULT_TIMEOUT = -1;

size_t Session::s_total_session_count = 0;

Session::Session(Service* _service, const Config& _config)
    : service(_service),
      udp_gc_timer(_service->get_io_context()),
      pipeline_com(_config),
      is_udp_forward(false),
      config(_config),
      session_name("Session"),
      udp_gc_timer_checker(steady_clock::now()) {
    s_total_session_count++;
}

Session::~Session() {
    s_total_session_count--;
    _log_with_date_time_ALL((is_udp_forward_session() ? "[udp] ~" : "[tcp] ~") + string(session_name) +
                            " called, current all sessions:  " + to_string(s_total_session_count));
}

int Session::get_udp_timer_timeout_val() const { return get_config().get_udp_timeout(); }

void Session::udp_timer_async_wait(int timeout /*=DEFAULT_TIMEOUT*/) {
    _guard;

    if (!is_udp_forward_session()) {
        return;
    }

    if (timeout == DEFAULT_TIMEOUT) {
        timeout = get_udp_timer_timeout_val();
    }

    auto now = steady_clock::now();
    if (udp_gc_timer_checker.time_since_epoch().count() != 0 && duration_cast<seconds>(now - udp_gc_timer_checker).count() < timeout) {
        udp_gc_timer_checker = now;
        return;
    }

    udp_gc_timer_checker = now;

    boost::system::error_code ec;
    udp_gc_timer.cancel(ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }

    udp_gc_timer.expires_after(seconds(timeout));
    auto self = shared_from_this();
    udp_gc_timer.async_wait([this, self, timeout](const boost::system::error_code& error) {
        _guard;
        if (!error) {
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - udp_gc_timer_checker).count() < timeout) {
                auto remaining = timeout - duration_cast<seconds>(now - udp_gc_timer_checker).count();
                udp_gc_timer_checker = steady_clock::time_point();
                udp_timer_async_wait(remaining);
                return;
            }

            _log_with_date_time("session_id: " + to_string(get_session_id()) + " UDP session timeout");
            destroy();
        } else if (error != boost::asio::error::operation_aborted) {
            output_debug_info_ec(error);
        }
        _unguard;
    });

    _unguard;
}

void Session::udp_timer_cancel() {
    _guard;

    if (udp_gc_timer_checker.time_since_epoch().count() == 0) {
        return;
    }

    boost::system::error_code ec;
    udp_gc_timer.cancel(ec);
    if (ec) {
        output_debug_info_ec(ec);
    }

    udp_gc_timer_checker = steady_clock::time_point();
    _unguard;
}
