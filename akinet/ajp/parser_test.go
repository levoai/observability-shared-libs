package ajp

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/levoai/observability-shared-libs/akinet"
	"github.com/levoai/observability-shared-libs/buffer_pool"
	"github.com/levoai/observability-shared-libs/memview"
)

var (
	testBidiID = akinet.TCPBidiID(uuid.MustParse("3744e3d7-2c08-4cd2-9ee9-2306dfba6727"))
)

func TestAJPRequestParser(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}

	forward := buildForwardRequest()
	bodyChunk := buildBodyChunk([]byte("field=test"))
	finalChunk := buildBodyChunk(nil)
	stream := append(append(forward, bodyChunk...), finalChunk...)

	parser := newAJPParser(true, testBidiID, 98, 512, pool)

	// Feed the request in two segments to ensure streaming operation is correct.
	result, unused, consumed, err := parser.Parse(memview.New(forward), false)
	if err != nil {
		t.Fatalf("unexpected error on first segment: %v", err)
	}
	if result != nil {
		t.Fatalf("expected no result for first segment")
	}
	if consumed != int64(len(forward)) {
		t.Fatalf("expected %d bytes consumed, got %d", len(forward), consumed)
	}

	result, unused, consumed, err = parser.Parse(memview.New(append(bodyChunk, finalChunk...)), true)
	if err != nil {
		t.Fatalf("unexpected error on final segment: %v", err)
	}
	if unused.Len() != 0 {
		t.Fatalf("expected no unused bytes, got %d", unused.Len())
	}

	req, ok := result.(akinet.HTTPRequest)
	if !ok {
		t.Fatalf("expected HTTPRequest, got %T", result)
	}
	defer req.ReleaseBuffers()

	expected := akinet.HTTPRequest{
		StreamID:   uuid.UUID(testBidiID),
		Seq:        512,
		Method:     http.MethodPost,
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL: &url.URL{
			Scheme:   "https",
			Host:     "service.internal",
			Path:     "/upload",
			RawPath:  "/upload",
			RawQuery: "q=1",
		},
		Host: "service.internal",
		Header: http.Header{
			"Host":               {"service.internal"},
			"Content-Length":     {"10"},
			"Content-Type":       {"application/x-www-form-urlencoded"},
			"Remote-User":        {"demo"},
			"Auth-Type":          {"basic"},
			"X-Ajp-Attr-Foo-Bar": {"123"},
		},
		Body: memview.New([]byte("field=test")),
	}

	if diff := cmp.Diff(expected, req, cmpopts.IgnoreUnexported(akinet.HTTPRequest{}), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("request diff (-want +got):\n%s", diff)
	}
	if consumed != int64(len(stream)) {
		t.Fatalf("expected %d bytes consumed, got %d", len(stream), consumed)
	}
}

func TestAJPResponseParser(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}

	sendHeaders := buildSendHeaders()
	body := buildBodyChunk([]byte("hello world"))
	endResp := buildEndResponse()
	stream := append(append(sendHeaders, body...), endResp...)

	parser := newAJPParser(false, testBidiID, 201, 600, pool)
	result, unused, consumed, err := parser.Parse(memview.New(stream), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unused.Len() != 0 {
		t.Fatalf("expected no unused bytes, got %d", unused.Len())
	}

	resp, ok := result.(akinet.HTTPResponse)
	if !ok {
		t.Fatalf("expected HTTPResponse, got %T", result)
	}
	defer resp.ReleaseBuffers()

	expected := akinet.HTTPResponse{
		StreamID:   uuid.UUID(testBidiID),
		Seq:        201,
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":   {"text/plain"},
			"Content-Length": {"11"},
			"Set-Cookie":     {"id=123"},
		},
		Cookies: []*http.Cookie{
			{Name: "id", Value: "123", Raw: "id=123"},
		},
		Body: memview.New([]byte("hello world")),
	}

	if diff := cmp.Diff(expected, resp, cmpopts.IgnoreUnexported(akinet.HTTPResponse{}), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("response diff (-want +got):\n%s", diff)
	}
	if consumed != int64(len(stream)) {
		t.Fatalf("expected %d bytes consumed, got %d", len(stream), consumed)
	}
}

func TestAJPResponseParserEOFWithoutEnd(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}

	sendHeaders := buildSendHeadersNoContentLength()
	body := buildBodyChunk([]byte("short"))
	stream := append(sendHeaders, body...)

	parser := newAJPParser(false, testBidiID, 500, 700, pool)
	result, unused, consumed, err := parser.Parse(memview.New(stream), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unused.Len() != 0 {
		t.Fatalf("expected no unused bytes, got %d", unused.Len())
	}

	resp, ok := result.(akinet.HTTPResponse)
	if !ok {
		t.Fatalf("expected HTTPResponse, got %T", result)
	}
	defer resp.ReleaseBuffers()

	expected := akinet.HTTPResponse{
		StreamID:   uuid.UUID(testBidiID),
		Seq:        500,
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"Set-Cookie":   {"id=456"},
		},
		Cookies: []*http.Cookie{
			{Name: "id", Value: "456", Raw: "id=456"},
		},
		Body: memview.New([]byte("short")),
	}

	if diff := cmp.Diff(expected, resp, cmpopts.IgnoreUnexported(akinet.HTTPResponse{}), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("response diff (-want +got):\n%s", diff)
	}
	if consumed != int64(len(stream)) {
		t.Fatalf("expected %d bytes consumed, got %d", len(stream), consumed)
	}
}

func TestAJPResponseParserAsciiMagic(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}

	sendHeaders := setMagic(buildSendHeaders(), ajpAsciiMagic)
	body := setMagic(buildBodyChunk([]byte("hi")), ajpAsciiMagic)
	endResp := setMagic(buildEndResponse(), ajpAsciiMagic)
	stream := append(append(sendHeaders, body...), endResp...)

	parser := newAJPParser(false, testBidiID, 301, 800, pool)
	result, _, _, err := parser.Parse(memview.New(stream), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(akinet.HTTPResponse)
	if !ok {
		t.Fatalf("expected HTTPResponse, got %T", result)
	}
	defer resp.ReleaseBuffers()

	if resp.StatusCode != 200 || resp.Body.String() != "hi" {
		t.Fatalf("unexpected response %+v", resp)
	}
}

func TestAJPFactoryAccept(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatal(err)
	}

	reqFactory := NewAJPRequestParserFactory(pool)
	respFactory := NewAJPResponseParserFactory(pool)

	forward := memview.New(buildForwardRequest())
	if decision, discard := reqFactory.Accepts(forward, false); decision != akinet.Accept || discard != 0 {
		t.Fatalf("request factory should accept forward request, got %v discard=%d", decision, discard)
	}

	partial := memview.New([]byte{0x12})
	if decision, _ := reqFactory.Accepts(partial, false); decision != akinet.NeedMoreData {
		t.Fatalf("expected NeedMoreData for partial magic, got %v", decision)
	}

	sendHeaders := memview.New(buildSendHeaders())
	if decision, discard := respFactory.Accepts(sendHeaders, false); decision != akinet.Accept || discard != 0 {
		t.Fatalf("response factory should accept send-headers, got %v discard=%d", decision, discard)
	}

	garbage := memview.New([]byte("hello"))
	if decision, discard := respFactory.Accepts(garbage, true); decision != akinet.Reject || discard != int64(len("hello")) {
		t.Fatalf("expected reject for garbage, got %v discard=%d", decision, discard)
	}

	// Ensure CPing frame is skipped when a forward request follows.
	cping := buildAjpMessage(ajpCPingRequestType, nil)
	cpingStream := append(cping, buildForwardRequest()...)
	cpingMem := memview.New(cpingStream)
	if decision, discard := reqFactory.Accepts(cpingMem, false); decision != akinet.Accept || discard != int64(len(cping)) {
		t.Fatalf("expected accept after skipping CPing, got %v discard=%d", decision, discard)
	}

	asciiSendHeaders := memview.New(setMagic(buildSendHeaders(), ajpAsciiMagic))
	if decision, discard := respFactory.Accepts(asciiSendHeaders, false); decision != akinet.Accept || discard != 0 {
		t.Fatalf("response factory should accept ascii magic, got %v discard=%d", decision, discard)
	}
}

func buildForwardRequest() []byte {
	payload := []byte{0x04} // POST
	payload = append(payload, ajpStringBytes("HTTP/1.1")...)
	payload = append(payload, ajpStringBytes("/upload")...)
	payload = append(payload, ajpStringBytes("192.168.0.10")...)
	payload = append(payload, ajpStringBytes("client.local")...)
	payload = append(payload, ajpStringBytes("app.internal")...)
	payload = append(payload, ajpUint16(8443)...)
	payload = append(payload, byte(0x01))      // is_ssl
	payload = append(payload, ajpUint16(3)...) // headers

	// Host
	payload = append(payload, ajpUint16(0xA00b)...)
	payload = append(payload, ajpStringBytes("service.internal")...)
	// Content-Type
	payload = append(payload, ajpUint16(0xA007)...)
	payload = append(payload, ajpStringBytes("application/x-www-form-urlencoded")...)
	// Content-Length
	payload = append(payload, ajpUint16(0xA008)...)
	payload = append(payload, ajpStringBytes("10")...)

	// Attributes
	payload = append(payload, scAQueryString)
	payload = append(payload, ajpStringBytes("q=1")...)
	payload = append(payload, scARemoteUser)
	payload = append(payload, ajpStringBytes("demo")...)
	payload = append(payload, scAAuthType)
	payload = append(payload, ajpStringBytes("basic")...)
	payload = append(payload, scAReqAttribute)
	payload = append(payload, ajpStringBytes("foo.bar")...)
	payload = append(payload, ajpStringBytes("123")...)
	payload = append(payload, scAAreDone)

	return buildAjpMessage(ajpForwardRequestType, payload)
}

func buildBodyChunk(data []byte) []byte {
	payload := ajpUint16(len(data))
	payload = append(payload, data...)
	payload = append(payload, 0x00)
	return buildAjpMessage(ajpSendBodyChunkType, payload)
}

func buildSendHeaders() []byte {
	payload := ajpUint16(200)
	payload = append(payload, ajpStringBytes("OK")...)
	payload = append(payload, ajpUint16(3)...) // headers
	// Content-Type
	payload = append(payload, ajpUint16(0xA001)...)
	payload = append(payload, ajpStringBytes("text/plain")...)
	// Content-Length
	payload = append(payload, ajpUint16(0xA003)...)
	payload = append(payload, ajpStringBytes("11")...)
	// Set-Cookie
	payload = append(payload, ajpUint16(0xA007)...)
	payload = append(payload, ajpStringBytes("id=123")...)
	return buildAjpMessage(ajpSendHeadersType, payload)
}

func buildSendHeadersNoContentLength() []byte {
	payload := ajpUint16(200)
	payload = append(payload, ajpStringBytes("OK")...)
	payload = append(payload, ajpUint16(2)...) // headers
	// Content-Type
	payload = append(payload, ajpUint16(0xA001)...)
	payload = append(payload, ajpStringBytes("text/plain")...)
	// Set-Cookie
	payload = append(payload, ajpUint16(0xA007)...)
	payload = append(payload, ajpStringBytes("id=456")...)
	return buildAjpMessage(ajpSendHeadersType, payload)
}

func buildEndResponse() []byte {
	return buildAjpMessage(ajpEndResponseType, []byte{0x01})
}

func buildAjpMessage(msgType byte, payload []byte) []byte {
	length := len(payload) + 1
	buf := make([]byte, 4, 4+length)
	buf[0] = ajpMagic[0]
	buf[1] = ajpMagic[1]
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	buf = append(buf, msgType)
	buf = append(buf, payload...)
	return buf
}

func ajpStringBytes(s string) []byte {
	if s == "" {
		return []byte{0x00, 0x00, 0x00}
	}
	length := len(s)
	buf := make([]byte, 2+length+1)
	buf[0] = byte(length >> 8)
	buf[1] = byte(length)
	copy(buf[2:], []byte(s))
	buf[len(buf)-1] = 0x00
	return buf
}

func ajpUint16(v int) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

func setMagic(msg []byte, magic []byte) []byte {
	if len(msg) < 2 {
		return msg
	}
	cp := make([]byte, len(msg))
	copy(cp, msg)
	copy(cp[:2], magic)
	return cp
}
