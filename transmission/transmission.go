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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/facebookgo/muster"
	"github.com/klauspost/compress/zstd"
	proxypb "github.com/opsramp/libtrace-go/proto/proxypb"
	"github.com/opsramp/libtrace-go/version"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

const (
	// Size limit for a serialized request body sent for a batch.
	apiMaxBatchSize int = 5000000 // 5MB
	// Size limit for a single serialized event within a batch.
	apiEventSizeMax    int = 100000 // 100KB
	maxOverflowBatches int = 10
	// Default start-to-finish timeout for batch send HTTP requests.
	defaultSendTimeout = time.Second * 60
)

var (
	// Libhoney's portion of the User-Agent header, e.g. "libhoney/1.2.3"
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

var Opsramptoken, OpsrampKey, OpsrampSecret, ApiEndPoint string
var mutex sync.Mutex
var conn *grpc.ClientConn
var opts []grpc.DialOption

type Opsramptraceproxy struct {
	// How many events to collect into a batch before sending. A
	// batch could be sent before achieving this item limit if the
	// BatchTimeout has elapsed since the last batch send. If set
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

	// how many batches can be inflight simultaneously
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

	OpsrampKey    string
	OpsrampSecret string
	ApiHost       string
}

type OpsRampAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (h *Opsramptraceproxy) Start() error {
	if h.Logger == nil {
		h.Logger = &nullLogger{}
	}
	h.Logger.Printf("default transmission starting")
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
				userAgentAddition: h.UserAgentAddition,
				batches:           map[string][]*Event{},
				httpClient: &http.Client{
					Transport: h.Transport,
					Timeout:   h.BatchSendTimeout,
				},
				blockOnResponse:       h.BlockOnResponse,
				responses:             h.responses,
				metrics:               h.Metrics,
				disableCompression:    h.DisableGzipCompression || h.DisableCompression,
				enableMsgpackEncoding: h.EnableMsgpackEncoding,
				logger:                h.Logger,
				useTls:                h.UseTls,
				useTlsInsecure:        h.UseTlsInsecure,
				OpsrampKey:            h.OpsrampKey,
				OpsrampSecret:         h.OpsrampSecret,
				ApiHost:               h.ApiHost,
			}
		}
	}

	OpsrampKey = h.OpsrampKey
	OpsrampSecret = h.OpsrampSecret
	ApiEndPoint = h.ApiHost
	mutex.Lock()
	var err error
	Opsramptoken, err = opsrampOauthToken()
	if err != nil {
		return err
	}
	mutex.Unlock()
	m := h.createMuster()
	h.muster = m
	return h.muster.Start()
}

func opsrampOauthToken() (string, error) {

	authTokenResponse := new(OpsRampAuthTokenResponse)

	u, err := url.Parse(ApiEndPoint)
	if err != nil {
		return "", err
	}

	authTokenURL := fmt.Sprintf("https://%s/auth/oauth/token", u.Host)

	req, err := http.NewRequest(
		http.MethodPost,
		authTokenURL,
		strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", OpsrampKey, OpsrampSecret)),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	err = json.Unmarshal(respBody, authTokenResponse)
	if err != nil {
		return "", err
	}

	return authTokenResponse.AccessToken, nil
}

func (h *Opsramptraceproxy) createMuster() *muster.Client {
	m := new(muster.Client)
	m.MaxBatchSize = h.MaxBatchSize
	m.BatchTimeout = h.BatchTimeout
	m.MaxConcurrentBatches = h.MaxConcurrentBatches
	m.PendingWorkCapacity = h.PendingWorkCapacity
	m.BatchMaker = h.batchMaker
	return m
}

func (h *Opsramptraceproxy) Stop() error {
	h.Logger.Printf("Opsramptraceproxy transmission stopping")
	err := h.muster.Stop()
	if conn != nil {
		conn.Close()
	}
	close(h.responses)
	return err
}

func (h *Opsramptraceproxy) Flush() (err error) {
	// There isn't a way to flush a muster.Client directly, so we have to stop
	// the old one (which has a side-effect of flushing the data) and make a new
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
func (h *Opsramptraceproxy) Add(ev *Event) {

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
func (h *Opsramptraceproxy) tryAdd(ev *Event) bool {
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

func (h *Opsramptraceproxy) TxResponses() chan Response {
	return h.responses
}

func (h *Opsramptraceproxy) SendResponse(r Response) bool {
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
	httpClient            *http.Client
	blockOnResponse       bool
	userAgentAddition     string
	disableCompression    bool
	enableMsgpackEncoding bool

	responses chan Response
	// numEncoded int

	metrics Metrics

	// allows manipulating value of "now" for testing
	testNower   nower
	testBlocker *sync.WaitGroup

	logger Logger

	useTls         bool
	useTlsInsecure bool
	OpsrampKey     string
	OpsrampSecret  string
	ApiHost        string
}

// batch is a collection of events that will all be POSTed as one HTTP call
// type batch []*Event

func (b *batchAgg) Add(ev interface{}) {
	// from muster godoc: "The Batch does not need to be safe for concurrent
	// access; synchronization will be handled by the Client."
	if b.batches == nil {
		b.batches = map[string][]*Event{}
	}
	e := ev.(*Event)
	// collect separate buckets of events to send based on the trio of api/wk/ds
	// if all three of those match it's safe to send all the events in one batch
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

	// send each batchKey's collection of event as a POST to /1/batch/<dataset>
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
				// fireBatch may append more overflow events
				// so we want to clear this key before firing the batch
				delete(b.overflowBatches, k)
				//b.fireBatch(events)
				//b.exportBatch(events)
				b.exportProtoMsgBatch(events)
			}
		}
	}
}

//type httpError interface {
//	Timeout() bool
//}

func (b *batchAgg) exportProtoMsgBatch(events []*Event) {
	var agent bool
	//start := time.Now().UTC()
	//if b.testNower != nil {
	//	start = b.testNower.Now()

	//}
	//b.metrics.Register("counterResponseErrors","counter")
	//b.metrics.Register("counterResponse20x","counter")
	if len(events) == 0 {
		// we managed to create a batch key with no events. odd. move on.
		return
	}

	var numEncoded int
	//var contentType string
	//contentType = "application/grpc"
	_, numEncoded = b.encodeBatchProtoBuf(events)

	// if we failed to encode any events skip this batch
	if numEncoded == 0 {
		return
	}
	//b.metrics.Register(d.Name+counterEnqueueErrors, "counter")
	//d.Metrics.Register(d.Name+counterResponse20x, "counter")
	//d.Metrics.Register(d.Name+counterResponseErrors, "counter")

	// get some attributes common to this entire batch up front off the first
	// valid event (some may be nil)
	var apiHost, tenantId, token, dataset string

	//var apiHost, writeKey, dataset string
	for _, ev := range events {
		if ev != nil {
			apiHost = ev.APIHost
			//writeKey = ev.APIKey
			dataset = ev.Dataset
			tenantId = ev.APITenantId
			if len(ev.APIToken) == 0 {
				token = Opsramptoken
				agent = false
			} else {
				token = ev.APIToken
				agent = true
			}
			break
		}
	}

	if tenantId == "" {
		b.logger.Printf("Skipping as TenantId is empty")
		return
	}

	apiHost = strings.Replace(apiHost, "https://", "", -1)
	apiHost = strings.Replace(apiHost, "http://", "", -1)
	var apiHostUrl string
	if !strings.Contains(apiHost, ":") {
		apiHostUrl = apiHost + ":443"
	} else {
		apiHostUrl = apiHost
	}

	retryCount := 3
	for i := 0; i < retryCount; i++ {
		if i > 0 {
			b.metrics.Increment("send_retries")
		}
		var err error
		if b.useTls {
			bInsecureSkip := b.useTlsInsecure

			tlsCfg := &tls.Config{
				InsecureSkipVerify: !bInsecureSkip,
			}

			tlsCreds := credentials.NewTLS(tlsCfg)
			b.logger.Printf("Connecting with Tls")
			opts = []grpc.DialOption{
				grpc.WithTransportCredentials(tlsCreds),
				grpc.WithUnaryInterceptor(grpcInterceptor),
			}

		} else {
			b.logger.Printf("Connecting without Tls")
			//conn, err = grpc.Dial(apiHostUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
			opts = []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithUnaryInterceptor(grpcInterceptor),
			}
		}
		if token != Opsramptoken && !agent {
			mutex.Lock()
			token = Opsramptoken
			mutex.Unlock()
		}

		if conn == nil || conn.GetState() == connectivity.TransientFailure || conn.GetState() == connectivity.Shutdown || string(conn.GetState()) == "INVALID_STATE" {
			mutex.Lock()
			conn, err = grpc.Dial(apiHostUrl, opts...)
			mutex.Unlock()
			if err != nil {
				b.logger.Printf("Could not connect: %v", err)
				b.metrics.Increment("send_errors")
				return
			}
		}

		c := proxypb.NewTraceProxyServiceClient(conn)

		req := proxypb.ExportTraceProxyServiceRequest{}

		req.TenantId = tenantId

		for _, ev := range events {
			b.logger.Printf("event data: %+v", ev.Data)

			traceData := proxypb.ProxySpan{}
			traceData.Data = &proxypb.Data{}

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
			traceData.Timestamp = ev.Timestamp.Format(time.RFC3339Nano)

			resourceAttr, _ := ev.Data["resourceAttributes"].(map[string]interface{})
			for key, val := range resourceAttr {
				resourceAttrKeyVal := proxypb.KeyValue{}
				resourceAttrKeyVal.Key = key

				switch v := val.(type) {
				case nil:
					b.logger.Printf("x is nil") // here v has type interface{}
				case string:
					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
				case bool:
					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
				case int64:
					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
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
					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
				case bool:
					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
				case int64:
					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
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
					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
				case bool:
					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
				case int64:
					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
				default:
					b.logger.Printf("type unknown: %v", v) // here v has type interface{}
				}

				traceData.Data.EventAttributes = append(traceData.Data.EventAttributes, &eventAttrKeyVal)
			}

			req.Items = append(req.Items, &traceData)

		}

		// Contact the server and print out its response.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		//Add headers
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(map[string]string{
			"Authorization": token,
			"tenantId":      tenantId,
			"dataset":       dataset,
		}))

		defer cancel()
		r, err := c.ExportTraceProxy(ctx, &req)
		if err != nil || r.GetStatus() == "" {
			b.logger.Printf("could not export traces from proxy in %v try: %v", i, err)
			b.metrics.Increment("send_errors")
			//b.metrics.Increment( "counterResponseErrors")
			continue
		} else {
			b.metrics.Increment("batches_sent")
			//b.metrics.Increment("counterResponse20x")
		}

		b.logger.Printf("trace proxy response: %s", r.String())
		b.logger.Printf("trace proxy response msg: %s", r.GetMessage())
		b.logger.Printf("trace proxy response status: %s", r.GetStatus())
		break
	}
}

var grpcInterceptor = func(ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	tokenChecker := fmt.Sprintf("Bearer %s", Opsramptoken)
	ctx = metadata.AppendToOutgoingContext(ctx, "Authorization", tokenChecker)
	err := invoker(ctx, method, req, reply, cc, opts...)
	if status.Code(err) == codes.Unauthenticated {
		// renew oauth token here before retry
		mutex.Lock()
		defer mutex.Unlock()
		Opsramptoken, err = opsrampOauthToken()
		if err != nil {
			return err
		}
	}
	return err
}

// create the JSON for this event list manually so that we can send
// responses down the response queue for any that fail to marshal
func (b *batchAgg) encodeBatchJSON(events []*Event) ([]byte, int) {

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
			// nil out the invalid Event so we can line up sent Events with server
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

		// ok, we have valid JSON and it'll fit in this batch; add ourselves a comma and the next value
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
			// nil out the invalid Event so we can line up sent Events with server
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

		// ok, we have valid JSON and it'll fit in this batch; add ourselves a comma and the next value
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
	// at the end of this to properly prepend the header.

	var arrayHeader [5]byte
	var numEncoded int
	var buf bytes.Buffer

	// Prepend space for largest possible msgpack array header.
	buf.Write(arrayHeader[:])
	for i, ev := range events {
		evByt, err := msgpack.Marshal(ev)
		if err != nil {
			b.enqueueResponse(Response{
				Err:      err,
				Metadata: ev.Metadata,
			})
			// nil out the invalid Event so we can line up sent Events with server
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
		// Most Opsramp messages are smaller than this.
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

//package transmission
//
//// txClient handles the transmission of events to Opsramp.
////
//// Overview
////
//// Create a new instance of Client.
//// Set any of the public fields for which you want to override the defaults.
//// Call Start() to spin up the background goroutines necessary for transmission
//// Call Add(Event) to queue an event for transmission
//// Ensure Stop() is called to flush all in-flight messages.
//
//import (
//	"bytes"
//	"context"
//	"crypto/tls"
//	"encoding/json"
//	"errors"
//	"fmt"
//	"google.golang.org/grpc/codes"
//	"google.golang.org/grpc/credentials"
//	"google.golang.org/grpc/credentials/insecure"
//	"google.golang.org/grpc/metadata"
//	"google.golang.org/grpc/status"
//	"io"
//	"net/http"
//	"runtime"
//	"strings"
//	"sync"
//	"time"
//
//	"github.com/facebookgo/muster"
//	"github.com/klauspost/compress/zstd"
//	proxypb "github.com/opsramp/libtrace-go/proto/proxypb"
//	"github.com/opsramp/libtrace-go/version"
//	"github.com/vmihailenco/msgpack/v5"
//	"google.golang.org/grpc"
//	"google.golang.org/grpc/connectivity"
//)
//
//const (
//	// Size limit for a serialized request body sent for a batch.
//	apiMaxBatchSize int = 5000000 // 5MB
//	// Size limit for a single serialized event within a batch.
//	apiEventSizeMax    int = 100000 // 100KB
//	maxOverflowBatches int = 10
//	// Default start-to-finish timeout for batch send HTTP requests.
//	defaultSendTimeout = time.Second * 60
//)
//
//var (
//	// Libhoney's portion of the User-Agent header, e.g. "libhoney/1.2.3"
//	baseUserAgent = fmt.Sprintf("libtrace-go/%s", version.Version)
//	// Information about the runtime environment for inclusion in User-Agent
//	runtimeInfo = fmt.Sprintf("%s (%s/%s)", strings.Replace(runtime.Version(), "go", "go/", 1), runtime.GOOS, runtime.GOARCH)
//	// The default User-Agent when no additions have been given
//	defaultUserAgent = fmt.Sprintf("%s %s", baseUserAgent, runtimeInfo)
//)
//
//// Return a user-agent value including any additions made in the configuration
//func fmtUserAgent(addition string) string {
//	if addition != "" {
//		return fmt.Sprintf("%s %s %s", baseUserAgent, strings.TrimSpace(addition), runtimeInfo)
//	} else {
//		return defaultUserAgent
//	}
//}
//
//var Opsramptoken, OpsrampKey, OpsrampSecret, ApiEndPoint string
//var mutex sync.Mutex
//var conn *grpc.ClientConn
//var opts []grpc.DialOption
//
//type Opsramptraceproxy struct {
//	// How many events to collect into a batch before sending. A
//	// batch could be sent before achieving this item limit if the
//	// BatchTimeout has elapsed since the last batch send. If set
//	// to zero, batches will only be sent upon reaching the
//	// BatchTimeout. It is an error for both this and
//	// the BatchTimeout to be zero.
//	// Default: 50 (from Config.MaxBatchSize)
//	MaxBatchSize uint
//
//	// How often to send batches. Events queue up into a batch until
//	// this time has elapsed or the batch item limit is reached
//	// (MaxBatchSize), then the batch is sent to Honeycomb API.
//	// If set to zero, batches will only be sent upon reaching the
//	// MaxBatchSize item limit. It is an error for both this and
//	// the MaxBatchSize to be zero.
//	// Default: 100 milliseconds (from Config.SendFrequency)
//	BatchTimeout time.Duration
//
//	// The start-to-finish timeout for HTTP requests sending event
//	// batches to the Honeycomb API. Transmission will retry once
//	// when receiving a timeout, so total time spent attempting to
//	// send events could be twice this value.
//	// Default: 60 seconds.
//	BatchSendTimeout time.Duration
//
//	// how many batches can be inflight simultaneously
//	MaxConcurrentBatches uint
//
//	// how many events to allow to pile up
//	// if not specified, then the work channel becomes blocking
//	// and attempting to add an event to the queue can fail
//	PendingWorkCapacity uint
//
//	// whether to block or drop events when the queue fills
//	BlockOnSend bool
//
//	// whether to block or drop responses when the queue fills
//	BlockOnResponse bool
//
//	UserAgentAddition string
//
//	// toggles compression when sending batches of events
//	DisableCompression bool
//
//	// Deprecated, synonymous with DisableCompression
//	DisableGzipCompression bool
//
//	// set true to send events with msgpack encoding
//	EnableMsgpackEncoding bool
//
//	batchMaker func() muster.Batch
//	responses  chan Response
//
//	// Transport defines the behavior of the lower layer transport details.
//	// It is used as the Transport value for the constructed HTTP client that
//	// sends batches of events.
//	// Default: http.DefaultTransport
//	Transport http.RoundTripper
//
//	muster     *muster.Client
//	musterLock sync.RWMutex
//
//	Logger  Logger
//	Metrics Metrics
//
//	UseTls         bool
//	UseTlsInsecure bool
//
//	OpsrampKey    string
//	OpsrampSecret string
//	ApiHost       string
//}
//
//type OpsRampAuthTokenResponse struct {
//	AccessToken string `json:"access_token"`
//	TokenType   string `json:"token_type"`
//	ExpiresIn   int64  `json:"expires_in"`
//	Scope       string `json:"scope"`
//}
//
//func (h *Opsramptraceproxy) Start() error {
//	if h.Logger == nil {
//		h.Logger = &nullLogger{}
//	}
//	fmt.Println("default transmission starting")
//	h.responses = make(chan Response, h.PendingWorkCapacity*2)
//	if h.Metrics == nil {
//		h.Metrics = &nullMetrics{}
//	}
//	if h.BatchSendTimeout == 0 {
//		h.BatchSendTimeout = defaultSendTimeout
//	}
//	if h.batchMaker == nil {
//		h.batchMaker = func() muster.Batch {
//			return &batchAgg{
//				userAgentAddition: h.UserAgentAddition,
//				batches:           map[string][]*Event{},
//				httpClient: &http.Client{
//					Transport: h.Transport,
//					Timeout:   h.BatchSendTimeout,
//				},
//				blockOnResponse:       h.BlockOnResponse,
//				responses:             h.responses,
//				metrics:               h.Metrics,
//				disableCompression:    h.DisableGzipCompression || h.DisableCompression,
//				enableMsgpackEncoding: h.EnableMsgpackEncoding,
//				logger:                h.Logger,
//				useTls:                h.UseTls,
//				useTlsInsecure:        h.UseTlsInsecure,
//				OpsrampKey:            h.OpsrampKey,
//				OpsrampSecret:         h.OpsrampSecret,
//				ApiHost:               h.ApiHost,
//			}
//		}
//	}
//
//	OpsrampKey = h.OpsrampKey
//	OpsrampSecret = h.OpsrampSecret
//	ApiEndPoint = h.ApiHost
//	mutex.Lock()
//	Opsramptoken = opsrampOauthToken()
//	mutex.Unlock()
//	m := h.createMuster()
//	h.muster = m
//	return h.muster.Start()
//}
//
//var req *http.Request
//var respToken *http.Response
//var authError, respError, unMarshallError, reqError error
//var authToken, url string
//var tokenResponse OpsRampAuthTokenResponse
//
//func opsrampOauthToken() string {
//
//	url = fmt.Sprintf("%s/auth/oauth/token", strings.TrimRight(ApiEndPoint, "/"))
//	fmt.Println("in opsrampOauthToken urls was: ", url)
//	requestBody := strings.NewReader("client_id=" + OpsrampKey + "&client_secret=" + OpsrampSecret + "&grant_type=client_credentials")
//	req, reqError = http.NewRequest(http.MethodPost, url, requestBody)
//	fmt.Println(" in opsrampOauthToken reqError: ", reqError)
//	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
//	req.Header.Add("Accept", "application/json")
//	req.Header.Set("Connection", "close")
//
//	respToken, authError = http.DefaultClient.Do(req)
//	fmt.Println(" in opsrampOauthToken authError: ", authError)
//
//	if authError != nil {
//		fmt.Println("Error for getting auth token: ", authError)
//		return ""
//	}
//	defer respToken.Body.Close()
//	var respBody []byte
//	respBody, respError = io.ReadAll(respToken.Body)
//	unMarshallError = json.Unmarshal(respBody, &tokenResponse)
//	authToken = tokenResponse.AccessToken
//	return tokenResponse.AccessToken
//}
//
//func (h *Opsramptraceproxy) createMuster() *muster.Client {
//	m := new(muster.Client)
//	m.MaxBatchSize = h.MaxBatchSize
//	m.BatchTimeout = h.BatchTimeout
//	m.MaxConcurrentBatches = h.MaxConcurrentBatches
//	m.PendingWorkCapacity = h.PendingWorkCapacity
//	m.BatchMaker = h.batchMaker
//	return m
//}
//
//func (h *Opsramptraceproxy) Stop() error {
//	fmt.Println("Opsramptraceproxy transmission stopping")
//	err := h.muster.Stop()
//	if conn != nil {
//		conn.Close()
//	}
//	close(h.responses)
//	return err
//}
//
//func (h *Opsramptraceproxy) Flush() (err error) {
//	// There isn't a way to flush a muster.Client directly, so we have to stop
//	// the old one (which has a side-effect of flushing the data) and make a new
//	// one. We start the new one and swap it with the old one so that we minimize
//	// the time we hold the musterLock for.
//	newMuster := h.createMuster()
//	err = newMuster.Start()
//	if err != nil {
//		return err
//	}
//	h.musterLock.Lock()
//	m := h.muster
//	h.muster = newMuster
//	h.musterLock.Unlock()
//	return m.Stop()
//}
//
//// Add enqueues ev to be sent. If a Flush is in-progress, this will block until
//// it completes. Similarly, if BlockOnSend is set and the pending work is more
//// than the PendingWorkCapacity, this will block a Flush until more pending
//// work can be enqueued.
//func (h *Opsramptraceproxy) Add(ev *Event) {
//
//	if h.tryAdd(ev) {
//		h.Metrics.Increment("messages_queued")
//		return
//	}
//	h.Metrics.Increment("queue_overflow")
//	r := Response{
//		Err:      errors.New("queue overflow"),
//		Metadata: ev.Metadata,
//	}
//	h.Logger.Printf("got response code %d, error %s, and body %s",
//		r.StatusCode, r.Err, string(r.Body))
//	writeToResponse(h.responses, r, h.BlockOnResponse)
//}
//
//// tryAdd attempts to add ev to the underlying muster. It returns false if this
//// was unsucessful because the muster queue (muster.Work) is full.
//func (h *Opsramptraceproxy) tryAdd(ev *Event) bool {
//	h.musterLock.RLock()
//	defer h.musterLock.RUnlock()
//
//	// Even though this queue is locked against changing h.Muster, the Work queue length
//	// could change due to actions on the worker side, so make sure we only measure it once.
//	qlen := len(h.muster.Work)
//	h.Logger.Printf("adding event to transmission; queue length %d", qlen)
//	h.Metrics.Gauge("queue_length", qlen)
//
//	if h.BlockOnSend {
//		h.muster.Work <- ev
//		return true
//	} else {
//		select {
//		case h.muster.Work <- ev:
//			return true
//		default:
//			return false
//		}
//	}
//}
//
//func (h *Opsramptraceproxy) TxResponses() chan Response {
//	return h.responses
//}
//
//func (h *Opsramptraceproxy) SendResponse(r Response) bool {
//	if h.BlockOnResponse {
//		h.responses <- r
//	} else {
//		select {
//		case h.responses <- r:
//		default:
//			return true
//		}
//	}
//	return false
//}
//
//// batchAgg is a batch aggregator - it's actually collecting what will
//// eventually be one or more batches sent to the /1/batch/dataset endpoint.
//type batchAgg struct {
//	// map of batch keys to a list of events destined for that batch
//	batches map[string][]*Event
//	// Used to reenque events when an initial batch is too large
//	overflowBatches       map[string][]*Event
//	httpClient            *http.Client
//	blockOnResponse       bool
//	userAgentAddition     string
//	disableCompression    bool
//	enableMsgpackEncoding bool
//
//	responses chan Response
//	// numEncoded int
//
//	metrics Metrics
//
//	// allows manipulating value of "now" for testing
//	testNower   nower
//	testBlocker *sync.WaitGroup
//
//	logger Logger
//
//	useTls         bool
//	useTlsInsecure bool
//	OpsrampKey     string
//	OpsrampSecret  string
//	ApiHost        string
//}
//
//// batch is a collection of events that will all be POSTed as one HTTP call
//// type batch []*Event
//
//func (b *batchAgg) Add(ev interface{}) {
//	// from muster godoc: "The Batch does not need to be safe for concurrent
//	// access; synchronization will be handled by the Client."
//	if b.batches == nil {
//		b.batches = map[string][]*Event{}
//	}
//	e := ev.(*Event)
//	// collect separate buckets of events to send based on the trio of api/wk/ds
//	// if all three of those match it's safe to send all the events in one batch
//	key := fmt.Sprintf("%s_%s", e.APIHost, e.Dataset)
//	b.batches[key] = append(b.batches[key], e)
//}
//
//func (b *batchAgg) enqueueResponse(resp Response) {
//	if writeToResponse(b.responses, resp, b.blockOnResponse) {
//		if b.testBlocker != nil {
//			b.testBlocker.Done()
//		}
//	}
//}
//
//func (b *batchAgg) reenqueueEvents(events []*Event) {
//	if b.overflowBatches == nil {
//		b.overflowBatches = make(map[string][]*Event)
//	}
//	for _, e := range events {
//		key := fmt.Sprintf("%s_%s", e.APIHost, e.Dataset)
//		b.overflowBatches[key] = append(b.overflowBatches[key], e)
//	}
//}
//
//func (b *batchAgg) Fire(notifier muster.Notifier) {
//	defer notifier.Done()
//	fmt.Println("Entered into Fire")
//
//	// send each batchKey's collection of event as a POST to /1/batch/<dataset>
//	// we don't need the batch key anymore; it's done its sorting job
//	for _, events := range b.batches {
//		//b.fireBatch(events)
//		//b.exportBatch(events)
//		fmt.Println("calling exportProtoMsgBatch for events: ", events)
//		b.exportProtoMsgBatch(events)
//	}
//	// The initial batches could have had payloads that were greater than 5MB.
//	// The remaining events will have overflowed into overflowBatches
//	// Process these until complete. Overflow batches can also overflow, so we
//	// have to prepare to process it multiple times
//	overflowCount := 0
//	if b.overflowBatches != nil {
//		for len(b.overflowBatches) > 0 {
//			// We really shouldn't get here but defensively avoid an endless
//			// loop of re-enqueued events
//			if overflowCount > maxOverflowBatches {
//				break
//			}
//			overflowCount++
//			// fetch the keys in this map - we can't range over the map
//			// because it's possible that fireBatch will reenqueue more overflow
//			// events
//			keys := make([]string, len(b.overflowBatches))
//			i := 0
//			for k := range b.overflowBatches {
//				keys[i] = k
//				i++
//			}
//
//			for _, k := range keys {
//				events := b.overflowBatches[k]
//				// fireBatch may append more overflow events
//				// so we want to clear this key before firing the batch
//				delete(b.overflowBatches, k)
//				//b.fireBatch(events)
//				//b.exportBatch(events)
//				b.exportProtoMsgBatch(events)
//			}
//		}
//	}
//}
//
////type httpError interface {
////	Timeout() bool
////}
//
//func (b *batchAgg) exportProtoMsgBatch(events []*Event) {
//	fmt.Println("Entered into export protomsgBatch for event: ", events)
//	var agent bool
//	//start := time.Now().UTC()
//	//if b.testNower != nil {
//	//	start = b.testNower.Now()
//
//	//}
//	//b.metrics.Register("counterResponseErrors","counter")
//	//b.metrics.Register("counterResponse20x","counter")
//	if len(events) == 0 {
//		// we managed to create a batch key with no events. odd. move on.
//		return
//	}
//
//	var numEncoded int
//	//var contentType string
//	//contentType = "application/grpc"
//	_, numEncoded = b.encodeBatchProtoBuf(events)
//
//	// if we failed to encode any events skip this batch
//	if numEncoded == 0 {
//		return
//	}
//	//b.metrics.Register(d.Name+counterEnqueueErrors, "counter")
//	//d.Metrics.Register(d.Name+counterResponse20x, "counter")
//	//d.Metrics.Register(d.Name+counterResponseErrors, "counter")
//
//	// get some attributes common to this entire batch up front off the first
//	// valid event (some may be nil)
//	var apiHost, tenantId, token, dataset string
//
//	//var apiHost, writeKey, dataset string
//	for _, ev := range events {
//		if ev != nil {
//			apiHost = ev.APIHost
//			//writeKey = ev.APIKey
//			dataset = ev.Dataset
//			tenantId = ev.APITenantId
//			if len(ev.APIToken) == 0 {
//				token = Opsramptoken
//				fmt.Println("generated independent token: ", token)
//				agent = false
//			} else {
//				token = ev.APIToken
//				agent = true
//				fmt.Println("Using Token from request header: ", token)
//			}
//			break
//		}
//	}
//
//	if tenantId == "" {
//		b.logger.Printf("Skipping as TenantId is empty")
//		return
//	}
//
//	apiHost = strings.Replace(apiHost, "https://", "", -1)
//	apiHost = strings.Replace(apiHost, "http://", "", -1)
//	var apiHostUrl string
//	if !strings.Contains(apiHost, ":") {
//		apiHostUrl = apiHost + ":443"
//	} else {
//		apiHostUrl = apiHost
//	}
//
//	retryCount := 3
//	for i := 0; i < retryCount; i++ {
//		fmt.Println("Starting to export: ", i)
//		if token == "" {
//			fmt.Println("Skipping as authToken is empty: ", authError, " token was: ", authToken, " Opsramp Token was: ", Opsramptoken, " RespError: ", respError, " Unamrshalling Error: ", unMarshallError, " tokenResponse.AccessToken: ", tokenResponse.AccessToken, " tokenResponse.TokenType: ", tokenResponse.TokenType, " tokenResponse.ExpiresIn: ", tokenResponse.ExpiresIn, " tokenResponse.Scope: ", tokenResponse.Scope, "url: ", url)
//			continue
//		}
//		if i > 0 {
//			b.metrics.Increment("send_retries")
//		}
//		var err error
//		if b.useTls {
//			bInsecureSkip := b.useTlsInsecure
//
//			tlsCfg := &tls.Config{
//				InsecureSkipVerify: !bInsecureSkip,
//			}
//
//			tlsCreds := credentials.NewTLS(tlsCfg)
//			fmt.Println("Connecting with Tls")
//			opts = []grpc.DialOption{
//				grpc.WithTransportCredentials(tlsCreds),
//				grpc.WithUnaryInterceptor(grpcInterceptor),
//			}
//
//		} else {
//			fmt.Println("Connecting without Tls")
//			//conn, err = grpc.Dial(apiHostUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
//			opts = []grpc.DialOption{
//				grpc.WithTransportCredentials(insecure.NewCredentials()),
//				grpc.WithUnaryInterceptor(grpcInterceptor),
//			}
//		}
//		if token != Opsramptoken && !agent {
//			mutex.Lock()
//			token = Opsramptoken
//			mutex.Unlock()
//		}
//
//		if conn == nil || conn.GetState() == connectivity.TransientFailure || conn.GetState() == connectivity.Shutdown || string(conn.GetState()) == "INVALID_STATE" {
//			mutex.Lock()
//			conn, err = grpc.Dial(apiHostUrl, opts...)
//			mutex.Unlock()
//			if err != nil {
//				fmt.Println("Could not connect: %v", err)
//				b.metrics.Increment("send_errors")
//				return
//			}
//		}
//
//		c := proxypb.NewTraceProxyServiceClient(conn)
//
//		req := proxypb.ExportTraceProxyServiceRequest{}
//
//		req.TenantId = tenantId
//
//		for _, ev := range events {
//			fmt.Println("event data: %+v", ev.Data)
//
//			traceData := proxypb.ProxySpan{}
//			traceData.Data = &proxypb.Data{}
//
//			traceData.Data.TraceTraceID, _ = ev.Data["traceTraceID"].(string)
//			traceData.Data.TraceParentID, _ = ev.Data["traceParentID"].(string)
//			traceData.Data.TraceSpanID, _ = ev.Data["traceSpanID"].(string)
//			traceData.Data.TraceLinkTraceID, _ = ev.Data["traceLinkTraceID"].(string)
//			traceData.Data.TraceLinkSpanID, _ = ev.Data["traceLinkSpanID"].(string)
//			traceData.Data.Type, _ = ev.Data["type"].(string)
//			traceData.Data.MetaType, _ = ev.Data["metaType"].(string)
//			traceData.Data.SpanName, _ = ev.Data["spanName"].(string)
//			traceData.Data.SpanKind, _ = ev.Data["spanKind"].(string)
//			traceData.Data.SpanNumEvents, _ = ev.Data["spanNumEvents"].(int64)
//			traceData.Data.SpanNumLinks, _ = ev.Data["spanNumLinks"].(int64)
//			traceData.Data.StatusCode, _ = ev.Data["statusCode"].(int64)
//			traceData.Data.StatusMessage, _ = ev.Data["statusMessage"].(string)
//			traceData.Data.Time, _ = ev.Data["time"].(int64)
//			traceData.Data.DurationMs, _ = ev.Data["durationMs"].(float64)
//			traceData.Data.StartTime, _ = ev.Data["startTime"].(int64)
//			traceData.Data.EndTime, _ = ev.Data["endTime"].(int64)
//			traceData.Data.Error, _ = ev.Data["error"].(bool)
//			traceData.Data.FromProxy, _ = ev.Data["fromProxy"].(bool)
//			traceData.Data.ParentName, _ = ev.Data["parentName"].(string)
//			traceData.Timestamp = ev.Timestamp.Format(time.RFC3339Nano)
//
//			resourceAttr, _ := ev.Data["resourceAttributes"].(map[string]interface{})
//			for key, val := range resourceAttr {
//				resourceAttrKeyVal := proxypb.KeyValue{}
//				resourceAttrKeyVal.Key = key
//
//				switch v := val.(type) {
//				case nil:
//					b.logger.Printf("x is nil") // here v has type interface{}
//				case string:
//					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
//				case bool:
//					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
//				case int64:
//					resourceAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
//				default:
//					b.logger.Printf("type unknown: ", v) // here v has type interface{}
//				}
//
//				traceData.Data.ResourceAttributes = append(traceData.Data.ResourceAttributes, &resourceAttrKeyVal)
//			}
//			spanAttr, _ := ev.Data["spanAttributes"].(map[string]interface{})
//			for key, val := range spanAttr {
//				spanAttrKeyVal := proxypb.KeyValue{}
//				spanAttrKeyVal.Key = key
//				//spanAttrKeyVal.Value = val.(*proxypb.AnyValue)
//
//				switch v := val.(type) {
//				case nil:
//					b.logger.Printf("x is nil") // here v has type interface{}
//				case string:
//					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
//				case bool:
//					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
//				case int64:
//					spanAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
//				default:
//					b.logger.Printf("type unknown: %v", v) // here v has type interface{}
//				}
//
//				traceData.Data.SpanAttributes = append(traceData.Data.SpanAttributes, &spanAttrKeyVal)
//			}
//
//			eventAttr, _ := ev.Data["eventAttributes"].(map[string]interface{})
//			for key, val := range eventAttr {
//				eventAttrKeyVal := proxypb.KeyValue{}
//				eventAttrKeyVal.Key = key
//				//spanAttrKeyVal.Value = val.(*proxypb.AnyValue)
//
//				switch v := val.(type) {
//				case nil:
//					b.logger.Printf("x is nil") // here v has type interface{}
//				case string:
//					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_StringValue{StringValue: val.(string)}} // here v has type int
//				case bool:
//					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_BoolValue{BoolValue: val.(bool)}} // here v has type interface{}
//				case int64:
//					eventAttrKeyVal.Value = &proxypb.AnyValue{Value: &proxypb.AnyValue_IntValue{IntValue: val.(int64)}} // here v has type interface{}
//				default:
//					b.logger.Printf("type unknown: %v", v) // here v has type interface{}
//				}
//
//				traceData.Data.EventAttributes = append(traceData.Data.EventAttributes, &eventAttrKeyVal)
//			}
//
//			req.Items = append(req.Items, &traceData)
//
//		}
//
//		// Contact the server and print out its response.
//		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//		fmt.Println("trace-proxy token: ", token, "  tenant id: ", tenantId, " dataset: ", dataset)
//
//		//Add headers
//		ctx = metadata.NewOutgoingContext(ctx, metadata.New(map[string]string{
//			"Authorization": token,
//			"tenantId":      tenantId,
//			"dataset":       dataset,
//		}))
//
//		defer cancel()
//		r, err := c.ExportTraceProxy(ctx, &req)
//		md, _ := metadata.FromIncomingContext(ctx)
//		fmt.Println("ctx metadata is: ", md)
//		if err != nil || r.GetStatus() == "" {
//			fmt.Println("could not export traces from proxy in %v try: %v", i, err)
//			b.metrics.Increment("send_errors")
//			//b.metrics.Increment( "counterResponseErrors")
//			continue
//		} else {
//			b.metrics.Increment("batches_sent")
//			//b.metrics.Increment("counterResponse20x")
//		}
//
//		fmt.Println("trace proxy response: %s", r.String())
//		fmt.Println("trace proxy response msg: %s", r.GetMessage())
//		fmt.Println("trace proxy response status: %s", r.GetStatus())
//		break
//	}
//}
//
//var grpcInterceptor = func(ctx context.Context,
//	method string,
//	req interface{},
//	reply interface{},
//	cc *grpc.ClientConn,
//	invoker grpc.UnaryInvoker,
//	opts ...grpc.CallOption,
//) error {
//	tokenChecker := fmt.Sprintf("Bearer %s", Opsramptoken)
//	ctx = metadata.AppendToOutgoingContext(ctx, "Authorization", tokenChecker)
//	err := invoker(ctx, method, req, reply, cc, opts...)
//	if status.Code(err) == codes.Unauthenticated {
//		// renew oauth token here before retry
//		mutex.Lock()
//		Opsramptoken = opsrampOauthToken()
//		mutex.Unlock()
//	}
//	return err
//}
//
//// create the JSON for this event list manually so that we can send
//// responses down the response queue for any that fail to marshal
//func (b *batchAgg) encodeBatchJSON(events []*Event) ([]byte, int) {
//
//	// track first vs. rest events for commas
//	first := true
//	// track how many we successfully encode for later bookkeeping
//	var numEncoded int
//	buf := bytes.Buffer{}
//	buf.WriteByte('[')
//	bytesTotal := 1
//	// ok, we've got our array, let's populate it with JSON events
//	for i, ev := range events {
//		evByt, err := json.Marshal(ev)
//		// check all our errors first in case we need to skip batching this event
//		if err != nil {
//			b.enqueueResponse(Response{
//				Err:      err,
//				Metadata: ev.Metadata,
//			})
//			// nil out the invalid Event so we can line up sent Events with server
//			// responses if needed. don't delete to preserve slice length.
//			events[i] = nil
//			continue
//		}
//		// if the event is too large to ever send, add an error to the queue
//		if len(evByt) > apiEventSizeMax {
//			b.enqueueResponse(Response{
//				Err:      fmt.Errorf("event exceeds max event size of %d bytes, API will not accept this event", apiEventSizeMax),
//				Metadata: ev.Metadata,
//			})
//			events[i] = nil
//			continue
//		}
//
//		bytesTotal += len(evByt)
//		// count for the trailing ]
//		if bytesTotal+1 > apiMaxBatchSize {
//			b.reenqueueEvents(events[i:])
//			break
//		}
//
//		// ok, we have valid JSON and it'll fit in this batch; add ourselves a comma and the next value
//		if !first {
//			buf.WriteByte(',')
//			bytesTotal++
//		}
//		first = false
//		buf.Write(evByt)
//		numEncoded++
//	}
//	buf.WriteByte(']')
//	return buf.Bytes(), numEncoded
//}
//
//// create the JSON for this event list manually so that we can send
//// responses down the response queue for any that fail to marshal
//func (b *batchAgg) encodeBatchProtoBuf(events []*Event) ([]byte, int) {
//	// track first vs. rest events for commas
//
//	first := true
//	// track how many we successfully encode for later bookkeeping
//	var numEncoded int
//	buf := bytes.Buffer{}
//	buf.WriteByte('[')
//	bytesTotal := 1
//	// ok, we've got our array, let's populate it with JSON events
//	for i, ev := range events {
//		evByt, err := json.Marshal(ev)
//		// check all our errors first in case we need to skip batching this event
//		if err != nil {
//			b.enqueueResponse(Response{
//				Err:      err,
//				Metadata: ev.Metadata,
//			})
//			// nil out the invalid Event so we can line up sent Events with server
//			// responses if needed. don't delete to preserve slice length.
//			events[i] = nil
//			continue
//		}
//		// if the event is too large to ever send, add an error to the queue
//		if len(evByt) > apiEventSizeMax {
//			b.enqueueResponse(Response{
//				Err:      fmt.Errorf("event exceeds max event size of %d bytes, API will not accept this event", apiEventSizeMax),
//				Metadata: ev.Metadata,
//			})
//			events[i] = nil
//			continue
//		}
//
//		bytesTotal += len(evByt)
//		// count for the trailing ]
//		if bytesTotal+1 > apiMaxBatchSize {
//			b.reenqueueEvents(events[i:])
//			break
//		}
//
//		// ok, we have valid JSON and it'll fit in this batch; add ourselves a comma and the next value
//		if !first {
//			buf.WriteByte(',')
//			bytesTotal++
//		}
//		first = false
//		buf.Write(evByt)
//		numEncoded++
//	}
//	buf.WriteByte(']')
//	return buf.Bytes(), numEncoded
//}
//
//func (b *batchAgg) encodeBatchMsgp(events []*Event) ([]byte, int) {
//	// Msgpack arrays need to be prefixed with the number of elements, but we
//	// don't know in advance how many we'll encode, because the msgpack lib
//	// doesn't do size estimation. Also, the array header is of variable size
//	// based on array length, so we'll need to do some []byte shenanigans at
//	// at the end of this to properly prepend the header.
//
//	var arrayHeader [5]byte
//	var numEncoded int
//	var buf bytes.Buffer
//
//	// Prepend space for largest possible msgpack array header.
//	buf.Write(arrayHeader[:])
//	for i, ev := range events {
//		evByt, err := msgpack.Marshal(ev)
//		if err != nil {
//			b.enqueueResponse(Response{
//				Err:      err,
//				Metadata: ev.Metadata,
//			})
//			// nil out the invalid Event so we can line up sent Events with server
//			// responses if needed. don't delete to preserve slice length.
//			events[i] = nil
//			continue
//		}
//		// if the event is too large to ever send, add an error to the queue
//		if len(evByt) > apiEventSizeMax {
//			b.enqueueResponse(Response{
//				Err:      fmt.Errorf("event exceeds max event size of %d bytes, API will not accept this event", apiEventSizeMax),
//				Metadata: ev.Metadata,
//			})
//			events[i] = nil
//			continue
//		}
//
//		if buf.Len()+len(evByt) > apiMaxBatchSize {
//			b.reenqueueEvents(events[i:])
//			break
//		}
//
//		buf.Write(evByt)
//		numEncoded++
//	}
//
//	headerBuf := bytes.NewBuffer(arrayHeader[:0])
//	msgpack.NewEncoder(headerBuf).EncodeArrayLen(numEncoded)
//
//	// Shenanigans. Chop off leading bytes we don't need, then copy in header.
//	byts := buf.Bytes()[len(arrayHeader)-headerBuf.Len():]
//	copy(byts, headerBuf.Bytes())
//
//	return byts, numEncoded
//}
//
//func (b *batchAgg) enqueueErrResponses(err error, events []*Event, duration time.Duration) {
//	for _, ev := range events {
//		if ev != nil {
//			b.enqueueResponse(Response{
//				Err:      err,
//				Duration: duration,
//				Metadata: ev.Metadata,
//			})
//		}
//	}
//}
//
//var zstdBufferPool sync.Pool
//
//type pooledReader struct {
//	bytes.Reader
//	buf []byte
//}
//
//// Instantiating a new encoder is expensive, so use a global one.
//// EncodeAll() is concurrency-safe.
//var zstdEncoder *zstd.Encoder
//
//func init() {
//	var err error
//	zstdEncoder, err = zstd.NewWriter(
//		nil,
//		// Compression level 2 gives a good balance of speed and compression.
//		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(2)),
//		// zstd allocates 2 * GOMAXPROCS * window size, so use a small window.
//		// Most Opsramp messages are smaller than this.
//		zstd.WithWindowSize(1<<16),
//	)
//	if err != nil {
//		panic(err)
//	}
//}
//
//// nower to make testing easier
//type nower interface {
//	Now() time.Time
//}
