pub mod udp {
    use crate::UDPFilter;
    use std::net::SocketAddr;
    use tokio::sync::mpsc::UnboundedSender;

    use crate::netstack::netstack::UDPPacket;

    pub struct PassthroughUDP {}

    impl PassthroughUDP {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl UDPFilter for PassthroughUDP {
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

pub mod tcp {
    use crate::TCPFilter;
    use httparse::{Error, Request, Response};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    pub struct PassthroughTCP {}

    impl PassthroughTCP {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl TCPFilter for PassthroughTCP {
        fn on_source_read(&mut self, _data: &[u8]) {}
        fn on_destination_read(&mut self, _data: &[u8]) {}
    }

    #[derive(Debug)]
    enum HttpParserState {
        Headers,
        Body { length: usize },
        Error,
    }

    struct HttpParser<O: std::io::Write + Send> {
        buffer: Vec<u8>,
        state: HttpParserState,
        is_request: bool,
        output: O,
    }

    impl<Output: std::io::Write + Send> HttpParser<Output> {
        fn new(is_request: bool, output: Output) -> Self {
            HttpParser {
                buffer: Vec::new(),
                state: HttpParserState::Headers,
                is_request,
                output: output,
            }
        }

        // Returns the offset to the beginning of the body and the expected content length.
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
                    let log_line = match message {
                        Message::Req(request) => {
                            format!("--> {} {}", request.method.unwrap(), request.path.unwrap())
                        }
                        Message::Rsp(response) => {
                            format!("<-- {}", response.code.unwrap())
                        }
                    };

                    // Check for Content-Length header
                    let content_length = headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
                        .and_then(|h| str::from_utf8(h.value).ok())
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);

                    log::trace!("{}", str::from_utf8(&self.buffer).unwrap());

                    // TODO: Can be malformed req/resp - check if the request is
                    // GET/HEAD or the response is 204 No Content.
                    let result = self
                        .output
                        .write(format!("{} {} bytes\n", log_line, content_length).as_bytes());
                    match result {
                        Ok(_) => (),
                        Err(error) => {
                            log::error!("Failed to write HTTP status to output: {:?}", error)
                        }
                    };

                    Ok(Some((body_offset, content_length)))
                }
                // TODO bug below
                httparse::Status::Partial => Err(Error::TooManyHeaders),
            }
        }

        fn try_parse_body(&mut self, length: usize) -> Option<Vec<u8>> {
            if self.buffer.len() >= length {
                let body = self.buffer.drain(..length).collect();
                Some(body)
            } else {
                None
            }
        }

        fn on_data(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }

            self.buffer.extend_from_slice(data);
            loop {
                match self.state {
                    HttpParserState::Headers => {
                        if self.buffer.len() == 0 {
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
            let mut parser = HttpParser::new(true, mock);

            parser.on_data(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> GET /index.html 0 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_content() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock);

            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\naa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> POST /api 2 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_split_content() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock);

            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\naa");
            parser.on_data(b"aa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(b"--> POST /api 4 bytes\n").unwrap()
            )
        }

        #[test]
        fn test_request_parser_with_multiple_requests() {
            let mock = MockWriter { data: Vec::new() };
            let mut parser = HttpParser::new(true, mock);

            parser.on_data(b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n");
            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\naa");
            parser.on_data(b"aa");
            parser
                .on_data(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\naa");
            assert_eq!(
                str::from_utf8(&parser.stop().data).unwrap(),
                str::from_utf8(
                    b"--> GET /api 0 bytes\n--> POST /api 4 bytes\n--> POST /api 2 bytes\n"
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

    pub struct HttpFilter<Output: std::io::Write + Send> {
        request_parser: HttpParser<SharedWriter<Output>>,
        response_parser: HttpParser<SharedWriter<Output>>,
    }

    impl<Output: std::io::Write + Send> HttpFilter<Output> {
        pub fn new(output: Output) -> HttpFilter<Output> {
            let output = SharedWriter::new(output);
            HttpFilter {
                request_parser: HttpParser::new(true, output.clone()),
                response_parser: HttpParser::new(false, output),
            }
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
