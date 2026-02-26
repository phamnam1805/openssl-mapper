SSL_accept() 
    -1 -> handshake fail
    1 -> handshake successful

SSL_read()
    >1 -> Ok
    -1 -> SSL_ERROR_SSL -> SSL_shutdown()
SSL_shutdown() → select → read(drain) → read=0 (EOF)