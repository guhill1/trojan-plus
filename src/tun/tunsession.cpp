#include "tunsession.h"

#include <ostream>
#include <string>

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"

using namespace std;

TUNSession::TUNSession(Service* _service, bool _is_udp) : 
    Session(_service->config, _service->service()),
    m_service(_service), 
    m_recv_buf_ack_length(0),
    m_out_socket(_service->service(), _service->get_ssl_context()),
    m_out_resolver(_service->service()),
    m_destroyed(false),
    m_connected(false){

    is_udp_forward_session = _is_udp;
    allocate_session_id();
}

TUNSession::~TUNSession(){
    destroy();
    free_session_id();
}

void TUNSession::set_tcp_connect(boost::asio::ip::tcp::endpoint _local, boost::asio::ip::tcp::endpoint _remote){
    m_local_addr = _local;
    m_remote_addr = _remote;
}

void TUNSession::start(){
    auto self = shared_from_this();
    auto cb = [this, self](){
        m_connected  = true;

        m_send_buf = TrojanRequest::generate(config.password.cbegin()->first, 
            m_remote_addr.address().to_string(), m_remote_addr.port(), !is_udp_forward()) + m_send_buf;

        out_async_send(m_send_buf.c_str(), m_send_buf.length(), [this](boost::system::error_code ec){
            if(ec){
                output_debug_info_ec(ec);
                destroy();
                return;
            }

            out_async_read();
        });
        string().swap(m_send_buf); // free the recv buff
    };

    if(m_service->is_use_pipeline()){
        cb();
    }else{
        m_service->config.prepare_ssl_reuse(m_out_socket);
        auto self = shared_from_this();
        connect_remote_server_ssl(this, m_service->config.remote_addr, to_string(m_service->config.remote_port), 
            m_out_resolver, m_out_socket, m_local_addr,  cb);
    }
}

void TUNSession::destroy(bool pipeline_call){
    if(m_destroyed){
        return;
    }
    m_destroyed = true;
    
    _log_with_endpoint(m_local_addr, "TUNSession session_id: " + to_string(session_id) + " disconnected ", Log::INFO);

    m_wait_ack_handler.clear();
    m_out_resolver.cancel();   
    shutdown_ssl_socket(this, m_out_socket);

    if(!pipeline_call && m_service->is_use_pipeline()){
        pipeline_client_service->session_destroy_in_pipeline(*this);
    }
}

void TUNSession::pipeline_out_recv(string&& data){
    if (!m_service->is_use_pipeline()) {
        throw logic_error("cannot call pipeline_out_recv without pipeline!");
    }

    if (!is_destroyed()) {
        m_pipeline_data_cache.push_data(move(data));
    }    
}

void TUNSession::out_async_read() {
    if(m_service->is_use_pipeline()){
        m_pipeline_data_cache.async_read([this](const string &data) {
            ostream os(&m_recv_buf);
            os << data;

            m_recv_buf_ack_length += data.length();

            // don't need to call m_recv_buf.commit(length);
            if(m_write_to_lwip() < 0){
                output_debug_info();
                destroy();
            }
        });
    }else{

        auto self = shared_from_this();
        m_out_socket.async_read_some(m_recv_buf.prepare(Session::MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            if (error) {
                output_debug_info_ec(error);
                destroy();
                return;
            }
            m_recv_buf.commit(length);
            m_recv_buf_ack_length += length;

            if(m_write_to_lwip() < 0){
                output_debug_info();
                destroy();
            }
        });
    }
}
void TUNSession::recv_ack_cmd(){
    Session::recv_ack_cmd();
    if(!m_wait_ack_handler.empty()){
        m_wait_ack_handler.front()(boost::system::error_code());
        m_wait_ack_handler.pop_front();
    }
}
void TUNSession::out_async_send(const char* _data, size_t _length, Pipeline::SentHandler&& _handler){

    if(!m_connected){
        m_send_buf += string(_data, _length);
        return;
    }

    auto self = shared_from_this();
    if(m_service->is_use_pipeline()){

        m_service->session_async_send_to_pipeline(*this, PipelineRequest::DATA, string(_data, _length), 
        [this, self, _handler](const boost::system::error_code error) {
            if (error) {
                output_debug_info_ec(error);
                destroy();

                _handler(error);
            }else{
                if(!pre_call_ack_func()){
                    m_wait_ack_handler.emplace_back(move(_handler));
                    _log_with_endpoint(m_local_addr, "Cannot TUNSession::out_async_send ! Is waiting for ack");
                    return;
                }
                _log_with_endpoint(m_local_addr, "Permit to TUNSession::out_async_send ! ack:" + to_string(pipeline_ack_counter));

                _handler(error);
            }            
        });
    }else{        
        auto data_copy = make_shared<string>(_data, _length);
        boost::asio::async_write(m_out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, _handler](const boost::system::error_code error, size_t) {
            if (error) {
                output_debug_info_ec(error);
                destroy();
            }

            _handler(error);
        });
    }
}

void TUNSession::recv_buf_sent(uint16_t _length){
    m_recv_buf_ack_length -= _length;

    if(is_destroyed()){
        return;
    }

    if(m_recv_buf_ack_length <= 0){
        if(m_service->is_use_pipeline()){
            auto self = shared_from_this();
            m_service->session_async_send_to_pipeline(*this, PipelineRequest::ACK, "", [this, self](const boost::system::error_code error) {
                if (error) {
                    output_debug_info_ec(error);
                    destroy();
                    return;
                }

                out_async_read();
            });
        }else{
            out_async_read();
        }
    }
}

