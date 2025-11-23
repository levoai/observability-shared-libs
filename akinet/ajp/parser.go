package ajp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/memview"
)

const (
	ajpForwardRequestType byte = 0x02
	ajpSendBodyChunkType  byte = 0x03
	ajpSendHeadersType    byte = 0x04
	ajpEndResponseType    byte = 0x05
	ajpGetBodyChunkType   byte = 0x06
	ajpCPongReplyType     byte = 0x09
	ajpCPingRequestType   byte = 0x0A
)

var ajpMagic = []byte{0x12, 0x34}

var ajpMethodCodes = map[byte]string{
	0x01: http.MethodOptions,
	0x02: http.MethodGet,
	0x03: http.MethodHead,
	0x04: http.MethodPost,
	0x05: http.MethodPut,
	0x06: http.MethodDelete,
	0x07: http.MethodTrace,
	0x08: "PROPFIND",
	0x09: "PROPPATCH",
	0x0a: "MKCOL",
	0x0b: "COPY",
	0x0c: "MOVE",
	0x0d: "LOCK",
	0x0e: "UNLOCK",
	0x0f: "ACL",
	0x10: "REPORT",
	0x11: "VERSION-CONTROL",
	0x12: "CHECKIN",
	0x13: "CHECKOUT",
	0x14: "UNCHECKOUT",
	0x15: "SEARCH",
	0x16: "MKWORKSPACE",
	0x17: "UPDATE",
	0x18: "LABEL",
	0x19: "MERGE",
	0x1a: "BASELINE-CONTROL",
	0x1b: "MKACTIVITY",
}

var ajpRequestHeaderCodes = map[uint16]string{
	0xA001: "Accept",
	0xA002: "Accept-Charset",
	0xA003: "Accept-Encoding",
	0xA004: "Accept-Language",
	0xA005: "Authorization",
	0xA006: "Connection",
	0xA007: "Content-Type",
	0xA008: "Content-Length",
	0xA009: "Cookie",
	0xA00a: "Cookie2",
	0xA00b: "Host",
	0xA00c: "Pragma",
	0xA00d: "Referer",
	0xA00e: "User-Agent",
}

var ajpResponseHeaderCodes = map[uint16]string{
	0xA001: "Content-Type",
	0xA002: "Content-Language",
	0xA003: "Content-Length",
	0xA004: "Date",
	0xA005: "Last-Modified",
	0xA006: "Location",
	0xA007: "Set-Cookie",
	0xA008: "Set-Cookie2",
	0xA009: "Servlet-Engine",
	0xA00a: "Status",
	0xA00b: "WWW-Authenticate",
}

const (
	scAContext      byte = 0x01
	scAServletPath  byte = 0x02
	scARemoteUser   byte = 0x03
	scAAuthType     byte = 0x04
	scAQueryString  byte = 0x05
	scAJvmRoute     byte = 0x06
	scASSLCert      byte = 0x07
	scASSLCipher    byte = 0x08
	scASSLSession   byte = 0x09
	scAReqAttribute byte = 0x0a
	scASSLKeySize   byte = 0x0b
	scASecret       byte = 0x0c
	scAStoredMethod byte = 0x0d
	scAAreDone      byte = 0xff
)

type ajpParser struct {
	isRequest bool
	bidiID    akinet.TCPBidiID
	seq       reassembly.Sequence
	ack       reassembly.Sequence
	buffer    buffer_pool.Buffer
	pool      buffer_pool.BufferPool

	allInput    memview.MemView
	bytesParsed int64

	reqState  *ajpRequestState
	respState *ajpResponseState
}

var _ akinet.TCPParser = (*ajpParser)(nil)

func newAJPParser(isRequest bool, id akinet.TCPBidiID, seq, ack reassembly.Sequence, pool buffer_pool.BufferPool) *ajpParser {
	parser := &ajpParser{
		isRequest: isRequest,
		bidiID:    id,
		seq:       seq,
		ack:       ack,
		pool:      pool,
		buffer:    pool.NewBuffer(),
	}

	if isRequest {
		parser.reqState = newAJPRequestState()
	} else {
		parser.respState = newAJPResponseState()
	}

	return parser
}

func (p *ajpParser) Name() string {
	if p.isRequest {
		return "AJP Request Parser"
	}
	return "AJP Response Parser"
}

func (p *ajpParser) Parse(input memview.MemView, isEnd bool) (result akinet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	p.allInput.Append(input)
	totalBytesConsumed = p.allInput.Len()

	var consumed int64
	if p.isRequest {
		result, err = p.parseRequest()
	} else {
		result, err = p.parseResponse()
	}

	if err != nil {
		p.releaseBody()
		return nil, memview.MemView{}, totalBytesConsumed, err
	}

	if result == nil {
		if isEnd {
			p.releaseBody()
			return nil, memview.MemView{}, totalBytesConsumed, fmt.Errorf("incomplete AJP %s", p.nameSuffix())
		}
		return nil, memview.MemView{}, totalBytesConsumed, nil
	}

	consumed = p.bytesParsed
	unused = p.allInput.SubView(consumed, p.allInput.Len())
	totalBytesConsumed -= unused.Len()

	return result, unused, totalBytesConsumed, nil
}

func (p *ajpParser) nameSuffix() string {
	if p.isRequest {
		return "request"
	}
	return "response"
}

func (p *ajpParser) parseRequest() (akinet.ParsedNetworkContent, error) {
	state := p.reqState
	if state == nil {
		return nil, fmt.Errorf("AJP parser misconfigured without request state")
	}

	for {
		msg, needMore, err := p.nextMessage()
		if needMore {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		switch msg.msgType {
		case ajpForwardRequestType:
			if err := state.consumeForwardRequest(msg.payload); err != nil {
				return nil, err
			}
		case ajpSendBodyChunkType:
			chunkLen, err := p.appendBodyChunk(msg.payload)
			if err != nil {
				return nil, err
			}
			state.noteBodyChunk(chunkLen)
		case ajpCPingRequestType, ajpCPongReplyType:
			// Heartbeats are irrelevant to the HTTP payload; skip them.
		case ajpGetBodyChunkType:
			// Containers never send GET_BODY_CHUNK in this direction, but be lenient.
		case ajpEndResponseType:
			// Should not appear on request stream; treat as error to avoid desync.
			return nil, fmt.Errorf("unexpected END_RESPONSE on AJP request stream")
		default:
			return nil, fmt.Errorf("unsupported AJP message type 0x%x on request stream", msg.msgType)
		}

		if state.complete() {
			req, err := state.toHTTPRequest(p.buffer)
			if err != nil {
				return nil, err
			}
			result := akinet.FromStdRequest(uuid.UUID(p.bidiID), int(p.ack), req, p.buffer)
			p.buffer = nil
			return result, nil
		}
	}
}

func (p *ajpParser) parseResponse() (akinet.ParsedNetworkContent, error) {
	state := p.respState
	if state == nil {
		return nil, fmt.Errorf("AJP parser misconfigured without response state")
	}

	for {
		msg, needMore, err := p.nextMessage()
		if needMore {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		switch msg.msgType {
		case ajpSendHeadersType:
			if err := state.consumeSendHeaders(msg.payload); err != nil {
				return nil, err
			}
		case ajpSendBodyChunkType:
			chunkLen, err := p.appendBodyChunk(msg.payload)
			if err != nil {
				return nil, err
			}
			state.noteBodyChunk(chunkLen)
		case ajpEndResponseType:
			state.markEnd()
		case ajpGetBodyChunkType:
			// This is the server requesting additional request body bytes. Ignore.
		case ajpCPingRequestType, ajpCPongReplyType:
			// Ignore connection keepalive messages.
		case ajpForwardRequestType:
			return nil, fmt.Errorf("unexpected FORWARD_REQUEST on response stream")
		default:
			return nil, fmt.Errorf("unsupported AJP message type 0x%x on response stream", msg.msgType)
		}

		if state.complete() {
			resp, err := state.toHTTPResponse(p.buffer)
			if err != nil {
				return nil, err
			}
			result := akinet.FromStdResponse(uuid.UUID(p.bidiID), int(p.seq), resp, p.buffer)
			p.buffer = nil
			return result, nil
		}
	}
}

type ajpMessage struct {
	msgType byte
	payload memview.MemView
	length  int64
}

func (p *ajpParser) nextMessage() (msg ajpMessage, needMore bool, err error) {
	start := p.bytesParsed
	if p.allInput.Len()-start < 4 {
		return ajpMessage{}, true, nil
	}

	if p.allInput.GetByte(start) != ajpMagic[0] || p.allInput.GetByte(start+1) != ajpMagic[1] {
		return ajpMessage{}, false, fmt.Errorf("invalid AJP magic at offset %d", start)
	}

	payloadLen := int64(p.allInput.GetUint16(start + 2))
	totalLen := payloadLen + 4
	if p.allInput.Len()-start < totalLen {
		return ajpMessage{}, true, nil
	}

	payload := p.allInput.SubView(start+4, start+4+payloadLen)
	if payload.Len() == 0 {
		return ajpMessage{}, false, fmt.Errorf("AJP message missing type byte")
	}

	msgType := payload.GetByte(0)
	msg = ajpMessage{
		msgType: msgType,
		payload: payload.SubView(1, payload.Len()),
		length:  totalLen,
	}
	p.bytesParsed += totalLen
	return msg, false, nil
}

func (p *ajpParser) appendBodyChunk(payload memview.MemView) (int, error) {
	if payload.Len() < 2 {
		return 0, fmt.Errorf("malformed body chunk: missing length")
	}
	chunkLen := int(payload.GetUint16(0))
	dataEnd := int64(2 + chunkLen)
	if payload.Len() < dataEnd {
		return 0, fmt.Errorf("malformed body chunk: want %d bytes, have %d", chunkLen, payload.Len()-2)
	}
	if chunkLen > 0 {
		chunk := payload.SubView(2, dataEnd)
		if _, err := p.buffer.ReadFrom(chunk.CreateReader()); err != nil {
			return 0, err
		}
	}
	return chunkLen, nil
}

func (p *ajpParser) releaseBody() {
	if p.buffer != nil {
		p.buffer.Release()
		p.buffer = nil
	}
}

type ajpRequestState struct {
	headers     http.Header
	method      string
	proto       string
	protoMajor  int
	protoMinor  int
	reqURI      string
	remoteAddr  string
	remoteHost  string
	serverName  string
	serverPort  uint16
	isSSL       bool
	queryString string
	remoteUser  string
	authType    string
	attrs       map[string]string
	contentLen  int64
	bodyBytes   int64
	bodyDone    bool
	forwardSeen bool
}

func newAJPRequestState() *ajpRequestState {
	return &ajpRequestState{
		headers:    make(http.Header),
		attrs:      make(map[string]string),
		contentLen: -1,
	}
}

func (s *ajpRequestState) consumeForwardRequest(payload memview.MemView) error {
	if s.forwardSeen {
		return fmt.Errorf("duplicate FORWARD_REQUEST message")
	}
	reader := payload.CreateReader()
	methodCode, err := reader.ReadByte()
	if err != nil {
		return err
	}
	method, ok := ajpMethodCodes[methodCode]
	if !ok {
		return fmt.Errorf("unknown AJP method code 0x%x", methodCode)
	}
	proto, err := readAJPString(reader)
	if err != nil {
		return err
	}
	reqURI, err := readAJPString(reader)
	if err != nil {
		return err
	}
	remoteAddr, err := readAJPString(reader)
	if err != nil {
		return err
	}
	remoteHost, err := readAJPString(reader)
	if err != nil {
		return err
	}
	serverName, err := readAJPString(reader)
	if err != nil {
		return err
	}
	port, err := reader.ReadUint16()
	if err != nil {
		return err
	}
	isSSL, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if err := s.readHeaders(reader); err != nil {
		return err
	}
	if err := s.readAttributes(reader); err != nil {
		return err
	}

	major, minor, err := parseHTTPVersion(proto)
	if err != nil {
		return err
	}
	s.method = method
	s.proto = proto
	s.protoMajor = major
	s.protoMinor = minor
	s.reqURI = reqURI
	s.remoteAddr = remoteAddr
	s.remoteHost = remoteHost
	s.serverName = serverName
	s.serverPort = port
	s.isSSL = isSSL != 0
	s.forwardSeen = true

	if s.contentLen <= 0 {
		s.bodyDone = true
	}
	return nil
}

func (s *ajpRequestState) readHeaders(reader *memview.MemViewReader) error {
	numHeaders, err := reader.ReadUint16()
	if err != nil {
		return err
	}
	for i := 0; i < int(numHeaders); i++ {
		name, err := readAJPHeaderName(reader, ajpRequestHeaderCodes)
		if err != nil {
			return err
		}
		value, err := readAJPString(reader)
		if err != nil {
			return err
		}
		s.headers.Add(name, value)
		if strings.EqualFold(name, "Content-Length") {
			if cl, err := strconv.ParseInt(value, 10, 64); err == nil {
				s.contentLen = cl
				s.bodyDone = cl == 0
			}
		}
	}
	return nil
}

func (s *ajpRequestState) readAttributes(reader *memview.MemViewReader) error {
	for {
		code, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if code == scAAreDone {
			return nil
		}
		switch code {
		case scAQueryString:
			val, err := readAJPString(reader)
			if err != nil {
				return err
			}
			s.queryString = val
		case scARemoteUser:
			val, err := readAJPString(reader)
			if err != nil {
				return err
			}
			s.remoteUser = val
		case scAAuthType:
			val, err := readAJPString(reader)
			if err != nil {
				return err
			}
			s.authType = val
		case scAReqAttribute:
			name, err := readAJPString(reader)
			if err != nil {
				return err
			}
			val, err := readAJPString(reader)
			if err != nil {
				return err
			}
			s.attrs[name] = val
		case scAJvmRoute, scASSLCert, scASSLCipher, scASSLSession, scASecret, scAStoredMethod, scAContext, scAServletPath:
			val, err := readAJPString(reader)
			if err != nil {
				return err
			}
			s.attrs[attrName(code)] = val
		case scASSLKeySize:
			keySize, err := reader.ReadUint16()
			if err != nil {
				return err
			}
			s.attrs["ssl-key-size"] = strconv.Itoa(int(keySize))
		default:
			// Unknown attribute, treat as string to maintain alignment.
			if _, err := readAJPString(reader); err != nil {
				return err
			}
		}
	}
}

func (s *ajpRequestState) noteBodyChunk(length int) {
	s.bodyBytes += int64(length)
	if length == 0 {
		s.bodyDone = true
	} else {
		s.bodyDone = false
	}
}

func (s *ajpRequestState) complete() bool {
	return s.forwardSeen && s.bodyDone
}

func (s *ajpRequestState) toHTTPRequest(body buffer_pool.Buffer) (*http.Request, error) {
	if body == nil {
		return nil, fmt.Errorf("missing request body buffer")
	}
	if !s.forwardSeen {
		return nil, fmt.Errorf("no FORWARD_REQUEST parsed")
	}
	host := s.headers.Get("Host")
	if host == "" {
		host = s.derivedHost()
		if host != "" {
			s.headers.Set("Host", host)
		}
	}
	if s.remoteUser != "" {
		s.headers.Set("Remote-User", s.remoteUser)
	}
	if s.authType != "" {
		s.headers.Set("Auth-Type", s.authType)
	}
	for name, value := range s.attrs {
		if value == "" {
			continue
		}
		headerName := "X-Ajp-Attr-" + sanitizeHeaderName(name)
		s.headers.Set(headerName, value)
	}
	if s.reqURI == "" {
		s.reqURI = "/"
	}
	u := &url.URL{Path: s.reqURI, RawPath: s.reqURI}
	if s.queryString != "" {
		u.RawQuery = s.queryString
	}
	scheme := "http"
	if s.isSSL {
		scheme = "https"
	}
	u.Scheme = scheme
	if host != "" {
		u.Host = host
	}
	bodyView := body.Bytes()
	contentLength := s.contentLen
	if contentLength < 0 {
		contentLength = bodyView.Len()
	}
	req := &http.Request{
		Method:        s.method,
		URL:           u,
		Host:          host,
		Proto:         s.proto,
		ProtoMajor:    s.protoMajor,
		ProtoMinor:    s.protoMinor,
		Header:        s.headers,
		ContentLength: contentLength,
		Body:          io.NopCloser(bodyView.CreateReader()),
		RemoteAddr:    s.remoteAddr,
	}
	return req, nil
}

func (s *ajpRequestState) derivedHost() string {
	if s.serverName == "" {
		return ""
	}
	port := int(s.serverPort)
	if port == 0 {
		return s.serverName
	}
	defaultPort := 80
	if s.isSSL {
		defaultPort = 443
	}
	if port == defaultPort {
		return s.serverName
	}
	return net.JoinHostPort(s.serverName, strconv.Itoa(port))
}

type ajpResponseState struct {
	headers    http.Header
	statusCode int
	statusMsg  string
	contentLen int64
	bodyBytes  int64
	gotHeaders bool
	gotEnd     bool
	protoMajor int
	protoMinor int
}

func newAJPResponseState() *ajpResponseState {
	return &ajpResponseState{
		headers:    make(http.Header),
		contentLen: -1,
		protoMajor: 1,
		protoMinor: 1,
	}
}

func (s *ajpResponseState) consumeSendHeaders(payload memview.MemView) error {
	if s.gotHeaders {
		return fmt.Errorf("duplicate SEND_HEADERS message")
	}
	reader := payload.CreateReader()
	status, err := reader.ReadUint16()
	if err != nil {
		return err
	}
	statusMsg, err := readAJPString(reader)
	if err != nil {
		return err
	}
	numHeaders, err := reader.ReadUint16()
	if err != nil {
		return err
	}
	for i := 0; i < int(numHeaders); i++ {
		name, err := readAJPHeaderName(reader, ajpResponseHeaderCodes)
		if err != nil {
			return err
		}
		value, err := readAJPString(reader)
		if err != nil {
			return err
		}
		s.headers.Add(name, value)
		if strings.EqualFold(name, "Content-Length") {
			if cl, err := strconv.ParseInt(value, 10, 64); err == nil {
				s.contentLen = cl
			}
		}
	}
	s.statusCode = int(status)
	s.statusMsg = statusMsg
	s.gotHeaders = true
	return nil
}

func (s *ajpResponseState) noteBodyChunk(length int) {
	s.bodyBytes += int64(length)
}

func (s *ajpResponseState) markEnd() {
	s.gotEnd = true
}

func (s *ajpResponseState) complete() bool {
	return s.gotHeaders && s.gotEnd
}

func (s *ajpResponseState) toHTTPResponse(body buffer_pool.Buffer) (*http.Response, error) {
	if body == nil {
		return nil, fmt.Errorf("missing response body buffer")
	}
	if !s.gotHeaders {
		return nil, fmt.Errorf("no SEND_HEADERS parsed")
	}
	bodyView := body.Bytes()
	contentLength := s.contentLen
	if contentLength < 0 {
		contentLength = bodyView.Len()
	}
	proto := fmt.Sprintf("HTTP/%d.%d", s.protoMajor, s.protoMinor)
	resp := &http.Response{
		StatusCode:    s.statusCode,
		Status:        fmt.Sprintf("%d %s", s.statusCode, s.statusMsg),
		Proto:         proto,
		ProtoMajor:    s.protoMajor,
		ProtoMinor:    s.protoMinor,
		Header:        s.headers,
		ContentLength: contentLength,
		Body:          io.NopCloser(bodyView.CreateReader()),
	}
	return resp, nil
}

func readAJPHeaderName(reader *memview.MemViewReader, codes map[uint16]string) (string, error) {
	val, err := reader.ReadUint16()
	if err != nil {
		return "", err
	}
	if name, ok := codes[val]; ok {
		return name, nil
	}
	if val&0xFF00 == 0xA000 {
		return "", fmt.Errorf("unknown coded header 0x%x", val)
	}
	length := int(val)
	buf := make([]byte, length)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	terminator, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if terminator != 0x00 {
		return "", fmt.Errorf("header name missing terminator")
	}
	return string(buf), nil
}

func readAJPString(reader *memview.MemViewReader) (string, error) {
	length, err := reader.ReadUint16()
	if err != nil {
		return "", err
	}
	if length == 0xffff {
		return "", nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	terminator, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if terminator != 0x00 {
		return "", fmt.Errorf("AJP string missing terminator")
	}
	return string(buf), nil
}

func parseHTTPVersion(proto string) (int, int, error) {
	if proto == "" {
		return 1, 1, nil
	}
	if !strings.HasPrefix(proto, "HTTP/") {
		return 1, 1, fmt.Errorf("invalid HTTP version %q", proto)
	}
	parts := strings.SplitN(proto[5:], ".", 2)
	if len(parts) != 2 {
		return 1, 1, fmt.Errorf("invalid HTTP version %q", proto)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 1, 1, err
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 1, 1, err
	}
	return major, minor, nil
}

func sanitizeHeaderName(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') || ch == '-' {
			b.WriteByte(ch)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func attrName(code byte) string {
	switch code {
	case scAContext:
		return "context"
	case scAServletPath:
		return "servlet-path"
	case scAJvmRoute:
		return "jvm-route"
	case scASSLCert:
		return "ssl-cert"
	case scASSLCipher:
		return "ssl-cipher"
	case scASSLSession:
		return "ssl-session"
	case scASecret:
		return "secret"
	case scAStoredMethod:
		return "stored-method"
	default:
		return fmt.Sprintf("attr-0x%x", code)
	}
}
