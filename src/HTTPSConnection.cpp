#include "HTTPSConnection.hpp"

namespace httpsserver {


HTTPSConnection::HTTPSConnection(ResourceResolver * resResolver):
  HTTPConnection(resResolver) {
  #if (defined(PMGA_IDF_4))
    _ssl = NULL;
  #else
    _ssl = esp_tls_init();
  #endif
}

HTTPSConnection::~HTTPSConnection() {
  // Close the socket
  closeConnection();
}

bool HTTPSConnection::isSecure() {
  return true;
}

/**
 * Initializes the connection from a server socket.
 *
 * The call WILL BLOCK if accept(serverSocketID) blocks. So use select() to check for that in advance.
 */
#if (defined(PMGA_IDF_4))
int HTTPSConnection::initialize(int serverSocketID, SSL_CTX * sslCtx, HTTPHeaders *defaultHeaders) {
#else
int HTTPSConnection::initialize(int serverSocketID, esp_tls_cfg_server_t * cfgSrv, HTTPHeaders *defaultHeaders) {
#endif
  if (_connectionState == STATE_UNDEFINED) {
    // Let the base class connect the plain tcp socket
    int resSocket = HTTPConnection::initialize(serverSocketID, defaultHeaders);
    #if !(defined(PMGA_IDF_4))
    HTTPS_LOGI("Cert len:%d, apn:%s\n",cfgSrv->servercert_bytes,cfgSrv->alpn_protos[0]);
    #endif
    // Build up SSL Connection context if the socket has been created successfully
    #if (defined(PMGA_IDF_4))
    if (resSocket >= 0) {
      
      _ssl = SSL_new(sslCtx);
      
      if (_ssl) {
        // Bind SSL to the socket
        int success = SSL_set_fd(_ssl, resSocket);
      
        if (success) {
          // Perform the handshake
          success = SSL_accept(_ssl);
          if (success) {
            return resSocket;
          } else {
            HTTPS_LOGE("SSL_accept failed. Aborting handshake. FID=%d", resSocket);
          }
        } else {
          HTTPS_LOGE("SSL_set_fd failed. Aborting handshake. FID=%d", resSocket);
        }
      } else {
        HTTPS_LOGE("SSL_new failed. Aborting handshake. FID=%d", resSocket);
      }
    } 
    #else
        if (resSocket >= 0) {
      int res=esp_tls_server_session_create(cfgSrv,resSocket,_ssl);
      if (0==res) {
        esp_tls_cfg_server_session_tickets_init(cfgSrv);
        _cfg = cfgSrv;
        // Bind SSL to the socket
        if (ESP_OK == esp_tls_get_conn_sockfd(_ssl,&resSocket)) {
            return resSocket;
        } else {
             HTTPS_LOGE("SSL_accept failed. Aborting handshake. FID=%d", resSocket);
        }
      } else {
        HTTPS_LOGE("SSL_new failed. Aborting handshake. Error=%d", res);
      }
    } 
    #endif
    else {
      HTTPS_LOGE("Could not accept() new connection. FID=%d", resSocket);
    }

    _connectionState = STATE_ERROR;
    _clientState = CSTATE_ACTIVE;

    // This will only be called if the connection could not be established and cleanup
    // variables like _ssl etc.
    closeConnection();
  }
  // Error: The connection has already been established or could not be established
  return -1;
}


void HTTPSConnection::closeConnection() {

  // FIXME: Copy from HTTPConnection, could be done better probably
  if (_connectionState != STATE_ERROR && _connectionState != STATE_CLOSED) {

    // First call to closeConnection - set the timestamp to calculate the timeout later on
    if (_connectionState != STATE_CLOSING) {
      _shutdownTS = millis();
    }

    // Set the connection state to closing. We stay in closing as long as SSL has not been shutdown
    // correctly
    _connectionState = STATE_CLOSING;
  }

  // Try to tear down SSL while we are in the _shutdownTS timeout period or if an error occurred
  if (_ssl) {
    #if (defined(PMGA_IDF_4))
    if(_connectionState == STATE_ERROR || SSL_shutdown(_ssl) == 0) {
      // SSL_shutdown will return 1 as soon as the client answered with close notify
      // This means we are safe to close the socket
      SSL_free(_ssl);
      _ssl = NULL;
    } else if (_shutdownTS + HTTPS_SHUTDOWN_TIMEOUT < millis()) {
      // The timeout has been hit, we force SSL shutdown now by freeing the context
      SSL_free(_ssl);
      _ssl = NULL;
      HTTPS_LOGW("SSL_shutdown did not receive close notification from the client");
      _connectionState = STATE_ERROR;
    }
    #else
    esp_tls_cfg_server_session_tickets_free(_cfg);
    esp_tls_server_session_delete(_ssl);
    _ssl = NULL;
    _connectionState = STATE_ERROR;
    #endif
  }

  // If SSL has been brought down, close the socket
  if (!_ssl) {
    HTTPConnection::closeConnection();
  }
}

size_t HTTPSConnection::writeBuffer(byte* buffer, size_t length) {
  #if (defined(PMGA_IDF_4))
  return SSL_write(_ssl, buffer, length);
  #else
  esp_tls_conn_write(_ssl,buffer,length);
  #endif
}

size_t HTTPSConnection::readBytesToBuffer(byte* buffer, size_t length) {
  #if (defined(PMGA_IDF_4))
  int8_t ret = SSL_read(_ssl, buffer, length);
  if (ret < 0) {
    HTTPS_LOGD("SSL_read error: %d",  SSL_get_error(_ssl, ret));
  }
  return ret;
  #else
  return esp_tls_conn_read(_ssl, buffer, length);
  #endif
}

size_t HTTPSConnection::pendingByteCount() {
  #if (defined(PMGA_IDF_4))
  return SSL_pending(_ssl);
  #else
  return esp_tls_get_bytes_avail(_ssl);
  #endif
}

bool HTTPSConnection::canReadData() {
  #if (defined(PMGA_IDF_4))
  return HTTPConnection::canReadData() || (SSL_pending(_ssl) > 0);
  #else
  return HTTPConnection::canReadData() || (esp_tls_get_bytes_avail(_ssl) > 0);
  #endif
}

} /* namespace httpsserver */
