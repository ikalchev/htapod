/// This module contains ready to use implementations of a `UDPFilter`.
pub mod udp {
    use crate::UDPFilter;
    use std::net::SocketAddr;
    use tokio::sync::mpsc::UnboundedSender;

    use crate::netstack::netstack::UDPPacket;

    /// A "noop" UDP stack that just forwards UDP packets without inspecting them.
    ///
    /// Use this when you don't want special handling of UDP packets but still want
    /// to allow UDP traffic to pass from the tunnel interface to the outside world and
    /// vice versa.
    ///
    /// DNS for processes inside the network namespace will work.
    pub struct PassthroughUDP {}

    impl PassthroughUDP {
        /// Create a new `PassthroughUDP` stack.
        pub fn new() -> Self {
            Self {}
        }
    }

    impl Default for PassthroughUDP {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UDPFilter for PassthroughUDP {
        /// Forwards all packets from the tunnel interface to the outside world.
        fn handle_tun_udp(
            &mut self,
            data: Vec<u8>,
            local_address: SocketAddr,
            remote_address: SocketAddr,
            remote_sender: UnboundedSender<UDPPacket>,
        ) -> std::io::Result<()> {
            remote_sender
                .send(UDPPacket {
                    data,
                    local_address,
                    remote_address,
                })
                .map_err(|_send_error| {
                    std::io::Error::other("handle_tun_udp: Remote end is closed!")
                })
        }

        /// Forwards all packets from the outside world to the tunnel interface.
        fn handle_remote_udp(
            &mut self,
            data: Vec<u8>,
            local_address: SocketAddr,
            remote_address: SocketAddr,
            tun_sender: tokio::sync::mpsc::UnboundedSender<UDPPacket>,
        ) -> std::io::Result<()> {
            tun_sender
                .send(UDPPacket {
                    data,
                    local_address,
                    remote_address,
                })
                .map_err(|_send_error| {
                    std::io::Error::other("handle_remote_udp: Remote end is closed!")
                })
        }
    }
}

/// This module contains ready to use implementations of the `TCPFilter`.
///
/// - `PassthroughTCP` - A TCP filter that does nothing.
/// - `HTTPFilter` - A TCP filter that parses and summarizes HTTP <2 traffic going through `htapod`.
pub mod tcp {
    use crate::TCPFilter;
    use httparse::{Error, Request, Response};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// A "noop" TCP stack that does nothing.
    ///
    /// Use this when you don't want special handling of TCP packets but still want
    /// to allow TCP traffic to pass from the tunnel interface to the outside world and
    /// vice versa.
    pub struct PassthroughTCP {}

    impl PassthroughTCP {
        /// Creates a new `PassthroughTCP` filter.
        pub fn new() -> Self {
            Self {}
        }
    }

    impl Default for PassthroughTCP {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TCPFilter for PassthroughTCP {
        fn on_source_read(&mut self, _data: &[u8]) {}
        fn on_destination_read(&mut self, _data: &[u8]) {}
    }

    /// Represents the current state of the HTTP parser.
    #[doc(hidden)]
    #[derive(Debug)]
    enum HttpParserState {
        /// The parser hasn't parsed all headers yet.
        Headers,
        /// The parser has parsed all headers but not the whole body. The expected size
        /// of the body is `length`.
        Body { length: usize },
        /// The parser encountered an error.
        Error,
    }

    /// A naive HTTP <2 parser.
    #[doc(hidden)]
    struct HttpParser<O: std::io::Write + Send> {
        /// The currently read, but unprocessed, bytes.
        buffer: Vec<u8>,
        /// The current state.
        state: HttpParserState,
        /// Whether we are parsing a request or a response.
        is_request: bool,
        /// A writer to which to write HTTP summaries.
        output: O,
        /// Configuration for what to log.
        config: HttpFilterConfig,
        /// Start time for timing calculations.
        start_time: Option<std::time::Instant>,
    }

    impl<Output: std::io::Write + Send> HttpParser<Output> {
        /// Creates a new parser.
        #[doc(hidden)]
        fn new(is_request: bool, output: Output, config: HttpFilterConfig) -> Self {
            let config_clone = config.clone();
            HttpParser {
                buffer: Vec::new(),
                state: HttpParserState::Headers,
                is_request,
                output,
                config: config_clone,
                start_time: if config.log_timing {
                    Some(std::time::Instant::now())
                } else {
                    None
                },
            }
        }

        /// Attempts to parse the HTTP status line and headers.
        ///
        /// Returns the offset to the beginning of the body and the expected content length.
        ///
        /// Supports at most 16 headers.
        #[doc(hidden)]
        fn try_parse_headers(&mut self) -> Result<Option<(usize, usize)>, Error> {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            enum Message<'a, 'b> {
                Req(Request<'a, 'b>),
                Rsp(Response<'a, 'b>),
            }

            let (status, message) = if self.is_request {
                let mut request = Request::new(&mut headers);
                (request.parse(&self.buffer), Message::Req(request))
            } else {
                let mut response = Response::new(&mut headers);
                (response.parse(&self.buffer), Message::Rsp(response))
            };

            match status? {
                httparse::Status::Complete(body_offset) => {
                    let mut log_lines = Vec::new();

                    // Basic request/response line
                    let basic_line = match message {
                        Message::Req(request) => {
                            format!("--> {} {}", request.method.unwrap(), request.path.unwrap())
                        }
                        Message::Rsp(response) => {
                            format!("<-- {}", response.code.unwrap())
                        }
                    };
                    log_lines.push(basic_line);

                    // Check for Content-Length header
                    let content_length = headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
                        .and_then(|h| str::from_utf8(h.value).ok())
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);

                    // Log headers if configured
                    if (self.is_request && self.config.log_request_headers)
                        || (!self.is_request && self.config.log_response_headers)
                    {
                        for header in headers.iter() {
                            if !header.name.is_empty() {
                                let header_line = format!(
                                    "  {}: {}",
                                    header.name,
                                    str::from_utf8(header.value).unwrap_or("<invalid utf-8>")
                                );
                                log_lines.push(header_line);
                            }
                        }
                    }

                    // Add byte count
                    let byte_line = format!(
                        "{} {} bytes",
                        if self.is_request { ">>>" } else { "<<<" },
                        content_length
                    );
                    log_lines.push(byte_line);

                    // Add timing if configured
                    if let Some(start_time) = self.start_time {
                        let duration = start_time.elapsed();
                        let timing_line = format!("  Timing: {:?}", duration);
                        log_lines.push(timing_line);
                        self.start_time = Some(std::time::Instant::now()); // Reset for next message
                    }

                    log::trace!("{}", str::from_utf8(&self.buffer).unwrap());

                    // Write all log lines
                    for line in log_lines {
                        let result = self.output.write(format!("{}\n", line).as_bytes());
                        if let Err(error) = result {
                            log::error!("Failed to write HTTP status to output: {:?}", error);
                            break;
                        }
                    }

                    Ok(Some((body_offset, content_length)))
                }
                // TODO bug below
                httparse::Status::Partial => Err(Error::TooManyHeaders),
            }
        }

        /// Attempts to parse a body of the given length from the contents of the buffer.
        #[doc(hidden)]
        fn try_parse_body(&mut self, length: usize) -> Option<Vec<u8>> {
            if self.buffer.len() >= length {
                let body: Vec<u8> = self.buffer.drain(..length).collect();

                // Log body if configured and within size limits
                let should_log_body = if self.is_request {
                    self.config.log_request_bodies
                } else {
                    self.config.log_response_bodies
                };

                if should_log_body && body.len() <= self.config.max_body_size {
                    let body_str = str::from_utf8(&body).unwrap_or("<binary data>");
                    let body_line = if body_str.len() > 100 {
                        // Truncate long bodies
                        format!("  Body: {}... ({} bytes)", &body_str[..100], body.len())
                    } else {
                        format!("  Body: {}", body_str)
                    };

                    if let Err(error) = self.output.write(format!("{}\n", body_line).as_bytes()) {
                        log::error!("Failed to write HTTP body to output: {:?}", error);
                    }
                }

                Some(body)
            } else {
                None
            }
        }

        /// Process the newly read data from the wire.
        ///
        /// This method will continuously try to decode HTTP messages until it
        /// encounters an error or runs out of data.
        fn on_data(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }

            self.buffer.extend_from_slice(data);
            loop {
                match self.state {
                    HttpParserState::Headers => {
                        if self.buffer.is_empty() {
                            break;
                        }
                        match self.try_parse_headers() {
                            Ok(Some((body_offset, body_length))) => {
                                self.buffer.drain(..body_offset);
                                self.state = if body_length == 0 {
                                    HttpParserState::Headers
                                } else {
                                    HttpParserState::Body {
                                        length: body_length,
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => {
                                self.state = HttpParserState::Error;
                                break;
                            }
                        }
                    }
                    HttpParserState::Body { length } => {
                        match self.try_parse_body(length) {
                            Some(_message_bytes) => {
                                log::debug!(
                                    "Parsed full message! {}",
                                    str::from_utf8(&_message_bytes).unwrap()
                                );
                                //self.output.write(message_bytes.as_slice()).unwrap(); // TODO
                                self.state = HttpParserState::Headers;
                            }
                            None => break,
                        }
                    }
                    HttpParserState::Error => {
                        self.buffer.clear();
                        self.state = HttpParserState::Error;
                        break;
                    }
                }
            }
        }

        /// For testing - just get the writer so we can inspect it.
        #[doc(hidden)]
        #[cfg(test)]
        fn stop(self) -> Output {
            self.output
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct MockWriter {
            data: Vec<u8>,
        }

        impl std::io::Write for MockWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        #[test]
        fn test_request_parser_with_no_content() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock, HttpFilterConfig::default());

            parser.on_data(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> GET /index.html\n>>> 0 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_content() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock, HttpFilterConfig::default());

            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\naa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> POST /api\n>>> 2 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_split_content() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock, HttpFilterConfig::default());

            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\naa");
            parser.on_data(b"aa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> POST /api\n>>> 4 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_multiple_requests() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock, HttpFilterConfig::default());

            parser.on_data(b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n");
            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\naa");
            parser.on_data(b"aa");
            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\naa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(
                    b"--> GET /api\n>>> 0 bytes\n--> POST /api\n>>> 4 bytes\n--> POST /api\n>>> 2 bytes\n"
                )
                .unwrap()
            )
        }
    }

    struct SharedWriter<T: Write + Send> {
        inner: Arc<Mutex<T>>,
    }

    impl<T: Write + Send> SharedWriter<T> {
        pub fn new(writer: T) -> Self {
            SharedWriter {
                inner: Arc::new(Mutex::new(writer)),
            }
        }

        pub fn clone(&self) -> Self {
            SharedWriter {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    impl<T: Write + Send> Write for SharedWriter<T> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self.inner.lock().unwrap();
            guard.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let mut guard = self.inner.lock().unwrap();
            guard.flush()
        }
    }

    /// Configuration for HTTP filtering.
    #[derive(Debug, Clone)]
    pub struct HttpFilterConfig {
        pub log_request_headers: bool,
        pub log_response_headers: bool,
        pub log_request_bodies: bool,
        pub log_response_bodies: bool,
        pub max_body_size: usize,
        pub log_timing: bool,
    }

    impl Default for HttpFilterConfig {
        fn default() -> Self {
            Self {
                log_request_headers: false,
                log_response_headers: false,
                log_request_bodies: false,
                log_response_bodies: false,
                max_body_size: 1024, // 1KB default
                log_timing: false,
            }
        }
    }

    /// A `TCPFilter` that parses and summarizes HTTP <2 messages.
    ///
    /// For every parsed request, it will write a line
    /// `--> <METHOD> <PATH> <body length> bytes`
    /// in the writer and for every parsed response, it will write a line
    /// `<-- <STATUS CODE> <body length> bytes`.
    ///
    /// With enhanced configuration, it can log headers, bodies, and timing information.
    pub struct HttpFilter<Output: std::io::Write + Send> {
        request_parser: HttpParser<SharedWriter<Output>>,
        response_parser: HttpParser<SharedWriter<Output>>,
        config: HttpFilterConfig,
    }

    impl<Output: std::io::Write + Send> HttpFilter<Output> {
        /// Create a new HTTP filter with default configuration.
        pub fn new(output: Output) -> HttpFilter<Output> {
            Self::new_with_config(output, HttpFilterConfig::default())
        }

        /// Create a new HTTP filter with custom configuration.
        pub fn new_with_config(output: Output, config: HttpFilterConfig) -> HttpFilter<Output> {
            let output = SharedWriter::new(output);
            HttpFilter {
                request_parser: HttpParser::new(true, output.clone(), config.clone()),
                response_parser: HttpParser::new(false, output, config.clone()),
                config,
            }
        }

        /// Get the current configuration.
        pub fn config(&self) -> &HttpFilterConfig {
            &self.config
        }
    }

    impl<Output: std::io::Write + Send> TCPFilter for HttpFilter<Output> {
        fn on_source_read(&mut self, data: &[u8]) {
            self.request_parser.on_data(data);
        }
        fn on_destination_read(&mut self, data: &[u8]) {
            self.response_parser.on_data(data);
        }
    }
}
