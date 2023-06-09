package transmission

// txClient handles the transmission of events to Opsramp.
//
// Overview
//
// Create a new instance of Client.
// Set any of the public fields for which you want to override the defaults.
// Call Start() to spin up the background goroutines necessary for transmission
// Call Add(Event) to queue an event for transmission
// Ensure Stop() is called to flush all in-flight messages.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/facebookgo/muster"
	"github.com/klauspost/compress/zstd"
	"github.com/opsramp/libtrace-go/proto/proxypb"
	"github.com/opsramp/libtrace-go/version"
	"github.com/vmihailenco/msgpack/v5"
)

const unknownService = "unknown_service"

var possibleServiceNames = []string{"service_name", "service.name"}

const (
	// Size limit for a serialized request body sent for a batch.
	apiMaxBatchSize int = 5000000 // 5MB
	// Size limit for a single serialized event within a batch.
	apiEventSizeMax    int = 100000 // 100KB
	maxOverflowBatches int = 10
	// Default start-to-finish timeout for batch to send HTTP requests.
	defaultSendTimeout = time.Second * 60
)

var (
	// LibTrace's portion of the User-Agent header, e.g. "libhoney/1.2.3"
	baseUserAgent = fmt.Sprintf("libtrace-go/%s", version.Version)
	// Information about the runtime environment for inclusion in User-Agent
	runtimeInfo = fmt.Sprintf("%s (%s/%s)", strings.Replace(runtime.Version(), "go", "go/", 1), runtime.GOOS, runtime.GOARCH)
	// The default User-Agent when no additions have been given
	defaultUserAgent = fmt.Sprintf("%s %s", baseUserAgent, runtimeInfo)
)

// Return a user-agent value including any additions made in the configuration
func fmtUserAgent(addition string) string {
	if addition != "" {
		return fmt.Sprintf("%s %s %s", baseUserAgent, strings.TrimSpace(addition), runtimeInfo)
	} else {
		return defaultUserAgent
	}
}

type TraceProxy struct {
	// How many events to collect into a batch before sending. A
	// batch could be sent before achieving this item limit if the
	// BatchTimeout has elapsed since the last batch is sent. If set
	// to zero, batches will only be sent upon reaching the
	// BatchTimeout. It is an error for both this and
	// the BatchTimeout to be zero.
	// Default: 50 (from Config.MaxBatchSize)
	MaxBatchSize uint

	// How often to send batches. Events queue up into a batch until
	// this time has elapsed or the batch item limit is reached
	// (MaxBatchSize), then the batch is sent to Honeycomb API.
	// If set to zero, batches will only be sent upon reaching the
	// MaxBatchSize item limit. It is an error for both this and
	// the MaxBatchSize to be zero.
	// Default: 100 milliseconds (from Config.SendFrequency)
	BatchTimeout time.Duration

	// The start-to-finish timeout for HTTP requests sending event
	// batches to the Honeycomb API. Transmission will retry once
	// when receiving a timeout, so total time spent attempting to
	// send events could be twice this value.
	// Default: 60 seconds.
	BatchSendTimeout time.Duration

	// number of batches that can be inflight simultaneously
	MaxConcurrentBatches uint

	// how many events to allow to pile up
	// if not specified, then the work channel becomes blocking
	// and attempting to add an event to the queue can fail
	PendingWorkCapacity uint

	// whether to block or drop events when the queue fills
	BlockOnSend bool

	// whether to block or drop responses when the queue fills
	BlockOnResponse bool

	UserAgentAddition string

	// toggles compression when sending batches of events
	DisableCompression bool

	// Deprecated, synonymous with DisableCompression
	DisableGzipCompression bool

	// set true to send events with msgpack encoding
	EnableMsgpackEncoding bool

	batchMaker func() muster.Batch
	responses  chan Response

	// Transport defines the behavior of the lower layer transport details.
	// It is used as the Transport value for the constructed HTTP client that
	// sends batches of events.
	// Default: http.DefaultTransport
	Transport http.RoundTripper

	muster     *muster.Client
	musterLock sync.RWMutex

	Logger  Logger
	Metrics Metrics

	UseTls         bool
	UseTlsInsecure bool

	IsPeer bool

	ApiHost string

	TenantId          string
	Dataset           string
	AuthTokenEndpoint string
	AuthTokenKey      string
	AuthTokenSecret   string
	RetrySettings     *RetrySettings

	defaultAuth *Auth
	client      proxypb.TraceProxyServiceClient
}

func (h *TraceProxy) Start() error {
	if h.Logger == nil {
		h.Logger = &nullLogger{}
	}
	if h.TenantId == "" {
		return fmt.Errorf("tenantId cant be empty")
	}

	// populate auth token
	if h.defaultAuth == nil {
		auth, err := CreateNewAuth(
			h.AuthTokenEndpoint,
			h.AuthTokenKey,
			h.AuthTokenSecret,
			time.Minute*4,
			h.Transport,
			h.RetrySettings,
			time.Minute*5,
		)
		if err != nil {
			return err
		}
		h.defaultAuth = auth
		h.defaultAuth.Start()
		h.defaultAuth.Renew()
	}

	// establish initial connection
	var opts []grpc.DialOption
	if h.UseTls {
		tlsCfg := &tls.Config{InsecureSkipVerify: h.UseTlsInsecure}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts, grpc.WithUnaryInterceptor(h.defaultAuth.UnaryClientInterceptor))

	apiHostURL, err := url.Parse(h.ApiHost)
	if err != nil {
		return err
	}
	apiPort := apiHostURL.Port()
	if apiPort == "" {
		apiPort = "443"
	}
	apiHost := fmt.Sprintf("%s:%s", apiHostURL.Hostname(), apiPort)
	conn, err := grpc.Dial(apiHost, opts...)
	if err != nil {
		return err
	}
	h.client = proxypb.NewTraceProxyServiceClient(conn)

	h.responses = make(chan Response, h.PendingWorkCapacity*2)
	if h.Metrics == nil {
		h.Metrics = &nullMetrics{}
	}
	if h.BatchSendTimeout == 0 {
		h.BatchSendTimeout = defaultSendTimeout
	}
	if h.batchMaker == nil {
		h.batchMaker = func() muster.Batch {
			return &batchAgg{
				userAgentAddition:     h.UserAgentAddition,
				batches:               map[string][]*Event{},
				client:                h.client,
				blockOnResponse:       h.BlockOnResponse,
				responses:             h.responses,
				metrics:               h.Metrics,
				disableCompression:    h.DisableGzipCompression || h.DisableCompression,
				enableMsgpackEncoding: h.EnableMsgpackEncoding,
				logger:                h.Logger,
				tenantId:              h.TenantId,
				dataset:               h.Dataset,
				isPeer:                h.IsPeer,
			}
		}
	}

	m := h.createMuster()
	h.muster = m
	return h.muster.Start()
}

func (h *TraceProxy) createMuster() *muster.Client {
	m := new(muster.Client)
	m.MaxBatchSize = h.MaxBatchSize
	m.BatchTimeout = h.BatchTimeout
	m.MaxConcurrentBatches = h.MaxConcurrentBatches
	m.PendingWorkCapacity = h.PendingWorkCapacity
	m.BatchMaker = h.batchMaker
	return m
}

func (h *TraceProxy) Stop() error {
	h.Logger.Printf("TraceProxy transmission stopping")
	err := h.muster.Stop()
	if h.responses != nil {
		close(h.responses)
	}
	if h.defaultAuth != nil {
		h.defaultAuth.Stop()
	}

	return err
}

func (h *TraceProxy) Flush() (err error) {
	// There isn't a way to flush a muster.Client directly, so we have to stop
	// the old one (which has a side effect of flushing the data) and make a new
	// one. We start the new one and swap it with the old one so that we minimize
	// the time we hold the musterLock for.
	newMuster := h.createMuster()
	err = newMuster.Start()
	if err != nil {
		return err
	}
	h.musterLock.Lock()
	m := h.muster
	h.muster = newMuster
	h.musterLock.Unlock()
	return m.Stop()
}

// Add enqueues ev to be sent. If a Flush is in-progress, this will block until
// it completes. Similarly, if BlockOnSend is set and the pending work is more
// than the PendingWorkCapacity, this will block a Flush until more pending
// work can be enqueued.
func (h *TraceProxy) Add(ev *Event) {

	if h.tryAdd(ev) {
		h.Metrics.Increment("messages_queued")
		return
	}
	h.Metrics.Increment("queue_overflow")
	r := Response{
		Err:      errors.New("queue overflow"),
		Metadata: ev.Metadata,
	}
	h.Logger.Printf("got response code %d, error %s, and body %s",
		r.StatusCode, r.Err, string(r.Body))
	writeToResponse(h.responses, r, h.BlockOnResponse)
}

// tryAdd attempts to add ev to the underlying muster. It returns false if this
// was unsucessful because the muster queue (muster.Work) is full.
func (h *TraceProxy) tryAdd(ev *Event) bool {
	h.musterLock.RLock()
	defer h.musterLock.RUnlock()

	// Even though this queue is locked against changing h.Muster, the Work queue length
	// could change due to actions on the worker side, so make sure we only measure it once.
	qlen := len(h.muster.Work)
	h.Logger.Printf("adding event to transmission; queue length %d", qlen)
	h.Metrics.Gauge("queue_length", qlen)

	if h.BlockOnSend {
		h.muster.Work <- ev
		return true
	} else {
		select {
		case h.muster.Work <- ev:
			return true
		default:
			return false
		}
	}
}

func (h *TraceProxy) TxResponses() chan Response {
	return h.responses
}

func (h *TraceProxy) SendResponse(r Response) bool {
	if h.BlockOnResponse {
		h.responses <- r
	} else {
		select {
		case h.responses <- r:
		default:
			return true
		}
	}
	return false
}

// batchAgg is a batch aggregator - it's actually collecting what will
// eventually be one or more batches sent to the /1/batch/dataset endpoint.
type batchAgg struct {
	// map of batch keys to a list of events destined for that batch
	batches map[string][]*Event
	// Used to reenque events when an initial batch is too large
	overflowBatches       map[string][]*Event
	blockOnResponse       bool
	userAgentAddition     string
	disableCompression    bool
	enableMsgpackEncoding bool

	responses chan Response
	// numEncoded int

	metrics Metrics

	// allows manipulating the value of "now" for testing
	testNower   nower
	testBlocker *sync.WaitGroup

	logger Logger

	useTls         bool
	useTlsInsecure bool

	tenantId string
	dataset  string
	isPeer   bool

	client proxypb.TraceProxyServiceClient
}

// batch is a collection of events that will all be POSTed as one HTTP call
// type batch []*Event

func (b *batchAgg) Add(ev interface{}) {
	// from muster godoc: "The Batch does not need to be safe for concurrent
	// access; the Client will handle synchronization."
	if b.batches == nil {
		b.batches = map[string][]*Event{}
	}
	e := ev.(*Event)
	// collect separate buckets of events to send based on apiHost and dataset
	key := fmt.Sprintf("%s_%s", e.APIHost, e.Dataset)
	b.batches[key] = append(b.batches[key], e)
}

func (b *batchAgg) enqueueResponse(resp Response) {
	if writeToResponse(b.responses, resp, b.blockOnResponse) {
		if b.testBlocker != nil {
			b.testBlocker.Done()
		}
	}
}

func (b *batchAgg) reenqueueEvents(events []*Event) {
	if b.overflowBatches == nil {
		b.overflowBatches = make(map[string][]*Event)
	}
	for _, e := range events {
		key := fmt.Sprintf("%s_%s", e.APIHost, e.Dataset)
		b.overflowBatches[key] = append(b.overflowBatches[key], e)
	}
}

func (b *batchAgg) Fire(notifier muster.Notifier) {
	defer notifier.Done()

	// send each batchKey's collection of events as a POST to /1/batch/<dataset>
	// we don't need the batch key anymore; it's done its sorting job
	for _, events := range b.batches {
		//b.fireBatch(events)
		//b.exportBatch(events)
		b.exportProtoMsgBatch(events)
	}
	// The initial batches could have had payloads that were greater than 5MB.
	// The remaining events will have overflowed into overflowBatches
	// Process these until complete. Overflow batches can also overflow, so we
	// have to prepare to process it multiple times
	overflowCount := 0
	if b.overflowBatches != nil {
		for len(b.overflowBatches) > 0 {
			// We really shouldn't get here but defensively avoid an endless
			// loop of re-enqueued events
			if overflowCount > maxOverflowBatches {
				break
			}
			overflowCount++
			// fetch the keys in this map - we can't range over the map
			// because it's possible that fireBatch will reenqueue more overflow
			// events
			keys := make([]string, len(b.overflowBatches))
			i := 0
			for k := range b.overflowBatches {
				keys[i] = k
				i++
			}

			for _, k := range keys {
				events := b.overflowBatches[k]
				// fireBatch may append more overflow events,
				// so we want to clear this key before firing the batch
				delete(b.overflowBatches, k)
				//b.fireBatch(events)
				//b.exportBatch(events)
				b.exportProtoMsgBatch(events)
			}
		}
	}
}

func (b *batchAgg) exportProtoMsgBatch(events []*Event) {
	if len(events) == 0 {
		// we managed to create a batch with no events. 🤔️ that's odd, let's move on.
		return
	}
	_, numEncoded := b.encodeBatchProtoBuf(events)
	if numEncoded == 0 {
		return
	}

	req := proxypb.ExportTraceProxyServiceRequest{
		TenantId: b.tenantId,
	}

	var apiHost string

	for _, ev := range events {
		if apiHost == "" {
			apiHost = ev.APIHost
		}

		traceData := proxypb.ProxySpan{
			Data:      &proxypb.Data{},
			Timestamp: ev.Timestamp.Format(time.RFC3339Nano),
		}

		traceData.Data.TraceTraceID, _ = ev.Data["traceTraceID"].(string)
		traceData.Data.TraceParentID, _ = ev.Data["traceParentID"].(string)
		traceData.Data.TraceSpanID, _ = ev.Data["traceSpanID"].(string)
		traceData.Data.TraceLinkTraceID, _ = ev.Data["traceLinkTraceID"].(string)
		traceData.Data.TraceLinkSpanID, _ = ev.Data["traceLinkSpanID"].(string)
		traceData.Data.Type, _ = ev.Data["type"].(string)
		traceData.Data.MetaType, _ = ev.Data["metaType"].(string)
		traceData.Data.SpanName, _ = ev.Data["spanName"].(string)
		traceData.Data.SpanKind, _ = ev.Data["spanKind"].(string)
		traceData.Data.SpanNumEvents, _ = ev.Data["spanNumEvents"].(int64)
		traceData.Data.SpanNumLinks, _ = ev.Data["spanNumLinks"].(int64)
		traceData.Data.StatusCode, _ = ev.Data["statusCode"].(int64)
		traceData.Data.StatusMessage, _ = ev.Data["statusMessage"].(string)
		traceData.Data.Time, _ = ev.Data["time"].(int64)
		traceData.Data.DurationMs, _ = ev.Data["durationMs"].(float64)
		traceData.Data.StartTime, _ = ev.Data["startTime"].(int64)
		traceData.Data.EndTime, _ = ev.Data["endTime"].(int64)
		traceData.Data.Error, _ = ev.Data["error"].(bool)
		traceData.Data.FromProxy, _ = ev.Data["fromProxy"].(bool)
		traceData.Data.ParentName, _ = ev.Data["parentName"].(string)

		resourceAttr, _ := ev.Data["resourceAttributes"].(map[string]interface{})

		isUnknownService := true
		for _, key := range possibleServiceNames {
			if _, ok := resourceAttr[key]; ok {
				isUnknownService = false
				break
			}
		}
		if isUnknownService {
			resourceAttr[possibleServiceNames[0]] = unknownService
		}

		for key, val := range resourceAttr {
			resourceAttrKeyVal := proxypb.KeyValue{}
			resourceAttrKeyVal.Key = key

			switch v := val.(type) {
			case nil:
				b.logger.Printf("x is nil") // here v has type interface{}
			case string:
				resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: v}} // here v has type int
			case bool:
				resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: v}} // here v has type interface{}
			case int64:
				resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: v}} // here v has type interface{}
			default:
				b.logger.Printf("type unknown: ", v) // here v has type interface{}
			}

			traceData.Data.ResourceAttributes = append(traceData.Data.ResourceAttributes, &resourceAttrKeyVal)
		}
		spanAttr, _ := ev.Data["spanAttributes"].(map[string]interface{})
		for key, val := range spanAttr {
			spanAttrKeyVal := proxypb.KeyValue{}
			spanAttrKeyVal.Key = key
			//spanAttrKeyVal.Value = val.(*proxypb.AnyValue)

			switch v := val.(type) {
			case nil:
				b.logger.Printf("x is nil") // here v has type interface{}
			case string:
				spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: v}} // here v has type int
			case bool:
				spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: v}} // here v has type interface{}
			case int64:
				spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: v}} // here v has type interface{}
			default:
				b.logger.Printf("type unknown: %v", v) // here v has type interface{}
			}

			traceData.Data.SpanAttributes = append(traceData.Data.SpanAttributes, &spanAttrKeyVal)
		}

		eventAttr, _ := ev.Data["eventAttributes"].(map[string]interface{})
		for key, val := range eventAttr {
			eventAttrKeyVal := proxypb.KeyValue{}
			eventAttrKeyVal.Key = key
			//spanAttrKeyVal.Value = val.(*proxypb.AnyValue)

			switch v := val.(type) {
			case nil:
				b.logger.Printf("x is nil") // here v has type interface{}
			case string:
				eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: v}} // here v has type int
			case bool:
				eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: v}} // here v has type interface{}
			case int64:
				eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: v}} // here v has type interface{}
			default:
				b.logger.Printf("type unknown: %v", v) // here v has type interface{}
			}

			traceData.Data.EventAttributes = append(traceData.Data.EventAttributes, &eventAttrKeyVal)
		}

		req.Items = append(req.Items, &traceData)
	}

	//Add headers
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.New(map[string]string{
		"tenantId": b.tenantId,
		"dataset":  b.dataset,
	}))

	if b.isPeer && apiHost != "" {
		var sendDirect bool
		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}

		apiHostURL, err := url.Parse(apiHost)
		if err != nil {
			sendDirect = true
			b.logger.Printf("sending directly, unable to parse peer url: %v", err)
		}
		apiPort := apiHostURL.Port()
		if apiPort == "" {
			apiPort = "80"
		}
		apiHost := fmt.Sprintf("%s:%s", apiHostURL.Hostname(), apiPort)
		conn, err := grpc.Dial(apiHost, opts...)
		if err != nil {
			sendDirect = true
			b.logger.Printf("sending directly, unable to establish connection to %s error: %v", apiHost, err)
		}
		if !sendDirect {
			b.client = proxypb.NewTraceProxyServiceClient(conn)
		}
	}

	r, err := b.client.ExportTraceProxy(ctx, &req)
	if st, ok := status.FromError(err); ok {
		if st.Code() != codes.OK {
			b.logger.Printf("sending failed. error: %s", st.String())
			b.metrics.Increment("send_errors")
		} else {
			b.metrics.Increment("batches_sent")
		}
	}

	b.logger.Printf("trace proxy response: %s", r.String())
	b.logger.Printf("trace proxy response msg: %s", r.GetMessage())
	b.logger.Printf("trace proxy response status: %s", r.GetStatus())
}

// create the JSON for this event list manually so that we can send
// responses down the response queue for any that fail to marshal
func (b *batchAgg) encodeBatchProtoBuf(events []*Event) ([]byte, int) {
	// track first vs. rest events for commas

	first := true
	// track how many we successfully encode for later bookkeeping
	var numEncoded int
	buf := bytes.Buffer{}
	buf.WriteByte('[')
	bytesTotal := 1
	// ok, we've got our array, let's populate it with JSON events
	for i, ev := range events {
		evByt, err := json.Marshal(ev)
		// check all our errors first in case we need to skip batching this event
		if err != nil {
			b.enqueueResponse(Response{
				Err:      err,
				Metadata: ev.Metadata,
			})
			// nil out the invalid Event, so we can line up sent Events with server
			// responses if needed. don't delete to preserve slice length.
			events[i] = nil
			continue
		}
		// if the event is too large to ever send, add an error to the queue
		if len(evByt) > apiEventSizeMax {
			b.enqueueResponse(Response{
				Err:      fmt.Errorf("event exceeds max event size of %d bytes, API will not accept this event", apiEventSizeMax),
				Metadata: ev.Metadata,
			})
			events[i] = nil
			continue
		}

		bytesTotal += len(evByt)
		// count for the trailing ]
		if bytesTotal+1 > apiMaxBatchSize {
			b.reenqueueEvents(events[i:])
			break
		}

		// ok, we have valid JSON, and it'll fit in this batch; add ourselves a comma and the next value
		if !first {
			buf.WriteByte(',')
			bytesTotal++
		}
		first = false
		buf.Write(evByt)
		numEncoded++
	}
	buf.WriteByte(']')
	return buf.Bytes(), numEncoded
}

func (b *batchAgg) encodeBatchMsgp(events []*Event) ([]byte, int) {
	// Msgpack arrays need to be prefixed with the number of elements, but we
	// don't know in advance how many we'll encode, because the msgpack lib
	// doesn't do size estimation. Also, the array header is of variable size
	// based on array length, so we'll need to do some []byte shenanigans at
	// the end of this to properly prepend the header.

	var arrayHeader [5]byte
	var numEncoded int
	var buf bytes.Buffer

	// Prepend space for the largest possible msgpack array header.
	buf.Write(arrayHeader[:])
	for i, ev := range events {
		evByt, err := msgpack.Marshal(ev)
		if err != nil {
			b.enqueueResponse(Response{
				Err:      err,
				Metadata: ev.Metadata,
			})
			// nil out the invalid Event, so we can line up sent Events with server
			// responses if needed. don't delete to preserve slice length.
			events[i] = nil
			continue
		}
		// if the event is too large to ever send, add an error to the queue
		if len(evByt) > apiEventSizeMax {
			b.enqueueResponse(Response{
				Err:      fmt.Errorf("event exceeds max event size of %d bytes, API will not accept this event", apiEventSizeMax),
				Metadata: ev.Metadata,
			})
			events[i] = nil
			continue
		}

		if buf.Len()+len(evByt) > apiMaxBatchSize {
			b.reenqueueEvents(events[i:])
			break
		}

		buf.Write(evByt)
		numEncoded++
	}

	headerBuf := bytes.NewBuffer(arrayHeader[:0])
	msgpack.NewEncoder(headerBuf).EncodeArrayLen(numEncoded)

	// Shenanigans. Chop off leading bytes we don't need, then copy in header.
	byts := buf.Bytes()[len(arrayHeader)-headerBuf.Len():]
	copy(byts, headerBuf.Bytes())

	return byts, numEncoded
}

func (b *batchAgg) enqueueErrResponses(err error, events []*Event, duration time.Duration) {
	for _, ev := range events {
		if ev != nil {
			b.enqueueResponse(Response{
				Err:      err,
				Duration: duration,
				Metadata: ev.Metadata,
			})
		}
	}
}

var zstdBufferPool sync.Pool

type pooledReader struct {
	bytes.Reader
	buf []byte
}

// Instantiating a new encoder is expensive, so use a global one.
// EncodeAll() is concurrency-safe.
var zstdEncoder *zstd.Encoder

func init() {
	var err error
	zstdEncoder, err = zstd.NewWriter(
		nil,
		// Compression level 2 gives a good balance of speed and compression.
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(2)),
		// zstd allocates 2 * GOMAXPROCS * window size, so use a small window.
		// most Opsramp messages are smaller than this.
		zstd.WithWindowSize(1<<16),
	)
	if err != nil {
		panic(err)
	}
}

// nower to make testing easier
type nower interface {
	Now() time.Time
}
