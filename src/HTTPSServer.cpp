#include "HTTPSServer.hpp"

namespace httpsserver {

#if !(defined(PMGA_IDF_4))
  constexpr const char * alpn_protos[] = { "http/1.1", NULL } ;
#endif

HTTPSServer::HTTPSServer(SSLCert * cert, const uint16_t port, const uint8_t maxConnections, const in_addr_t bindAddress):
  HTTPServer(port, maxConnections, bindAddress),
  _cert(cert) {

  // Configure runtime data
  #if (defined(PMGA_IDF_4))
    _sslctx = NULL;
  #else
    _cfg = new esp_tls_cfg_server();
    _cfg->alpn_protos = (const char **)alpn_protos;
    _cfg->cacert_buf = NULL;
    _cfg->cacert_bytes = 0;
    _cfg->servercert_buf =cert->getCertData();
    _cfg->servercert_bytes = cert->getCertLength();
    _cfg->serverkey_buf= cert->getPKData();
    _cfg->serverkey_bytes= cert->getPKLength();
  #endif
}

HTTPSServer::~HTTPSServer() {
#if !(defined(PMGA_IDF_4))
  free(_cfg);
#endif
}

/**
 * This method starts the server and begins to listen on the port
 */
uint8_t HTTPSServer::setupSocket() {
  if (!isRunning()) {
    #if (defined(PMGA_IDF_4))
      if (!setupSSLCTX()) {
        Serial.println("setupSSLCTX failed");
        return 0;
      }

      if (!setupCert()) {
        Serial.println("setupCert failed");
        SSL_CTX_free(_sslctx);
        _sslctx = NULL;
        return 0;
      }
    #else
      _cfg->servercert_buf= _cert->getCertData();
      _cfg->servercert_bytes = _cert->getCertLength();
      _cfg->serverkey_buf= _cert->getPKData();
      _cfg->serverkey_bytes= _cert->getPKLength();
    #endif

    if (HTTPServer::setupSocket()) {
      return 1;
    } else {
      Serial.println("setupSockets failed");
      #if (defined(PMGA_IDF_4))
      SSL_CTX_free(_sslctx);
      _sslctx = NULL;
      #endif
      return 0;
    }
  } else {
    return 1;
  }
}

void HTTPSServer::teardownSocket() {

  HTTPServer::teardownSocket();
  #if (defined(PMGA_IDF_4))
    // Tear down the SSL context
    SSL_CTX_free(_sslctx);
    _sslctx = NULL;
  #endif
}

int HTTPSServer::createConnection(int idx) {
  HTTPSConnection * newConnection = new HTTPSConnection(this);
  _connections[idx] = newConnection;
  #if (defined(PMGA_IDF_4))
    return newConnection->initialize(_socket, _sslctx, &_defaultHeaders);
  }

  /**
  * This method configures the ssl context that is used for the server
  */
  uint8_t HTTPSServer::setupSSLCTX() {
    _sslctx = SSL_CTX_new(TLSv1_2_server_method());
    if (_sslctx) {
      // Set SSL Timeout to 5 minutes
      SSL_CTX_set_timeout(_sslctx, 300);
      return 1;
    } else {
      _sslctx = NULL;
      return 0;
    }
  #else
    return newConnection->initialize(_socket, _cfg , &_defaultHeaders);
  #endif
}

/**
 * This method configures the certificate and private key for the given
 * ssl context
 */
uint8_t HTTPSServer::setupCert() {
  // Configure the certificate first
  #if (defined(PMGA_IDF_4))
    uint8_t ret = SSL_CTX_use_certificate_ASN1(
      _sslctx,
      _cert->getCertLength(),
      _cert->getCertData()
    );

    // Then set the private key accordingly
    if (ret) {
      ret = SSL_CTX_use_RSAPrivateKey_ASN1(
        _sslctx,
        _cert->getPKData(),
        _cert->getPKLength()
      );
  }

    return ret;

  #else
    _cfg->servercert_buf= _cert->getCertData();
    _cfg->servercert_bytes = _cert->getCertLength();
    _cfg->serverkey_buf= _cert->getPKData();
    _cfg->serverkey_bytes= _cert->getPKLength();
    return 1;
  #endif
}

} /* namespace httpsserver */
