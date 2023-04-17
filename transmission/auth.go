package transmission

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout = time.Minute * 4
)

type Auth struct {
	Endpoint string
	Key      string
	Secret   string

	Transport     http.RoundTripper
	Timeout       time.Duration
	RetrySettings *RetrySettings

	renewInProgress bool
	mut             sync.RWMutex
	lastRenewedTime time.Time
	authToken       AuthTokenResponse
}

type AuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

func CreateNewAuth(endpoint, key, secret string, timeout time.Duration, transport http.RoundTripper, retrySettings *RetrySettings) (*Auth, error) {
	if endpoint == "" || key == "" || secret == "" {
		return nil, fmt.Errorf("invalid credentials")
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	endpoint = fmt.Sprintf("%s://%s", endpointURL.Scheme, endpointURL.Hostname())

	if timeout.Seconds() < 0 {
		timeout = defaultTimeout
	}
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		}
	}
	if retrySettings == nil {
		retrySettings = NewDefaultRetrySettings()
	}

	return &Auth{
		Endpoint:        endpoint,
		Key:             key,
		Secret:          secret,
		Transport:       transport,
		Timeout:         timeout,
		RetrySettings:   retrySettings,
		mut:             sync.RWMutex{},
		lastRenewedTime: time.Time{},
		authToken:       AuthTokenResponse{},
	}, nil
}

// GetToken returns the stored authToken
func (oauth *Auth) GetToken() string {
	oauth.mut.RLock()
	defer oauth.mut.RUnlock()

	return oauth.authToken.AccessToken
}

// Valid checks if the auth token is populated and expiry time greater than 0
func (oauth *Auth) Valid() bool {
	oauth.mut.RLock()
	defer oauth.mut.RUnlock()

	return !oauth.lastRenewedTime.IsZero() &&
		oauth.authToken.AccessToken != "" &&
		oauth.authToken.ExpiresIn > 0
}

func (oauth *Auth) Renew() (string, error) {
	if oauth.renewInProgress {
		for oauth.renewInProgress {
			time.Sleep(time.Second * 5)
		}
		return oauth.authToken.AccessToken, nil
	}

	oauth.mut.Lock()
	defer oauth.mut.Unlock()
	oauth.renewInProgress = true
	defer func() { oauth.renewInProgress = false }()

	authTokenResponse := AuthTokenResponse{}

	authTokenURL := fmt.Sprintf("%s/auth/oauth/token", oauth.Endpoint)

	req, err := http.NewRequest(
		http.MethodPost,
		authTokenURL,
		strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", oauth.Key, oauth.Secret)),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")

	client := &http.Client{
		Timeout:   oauth.Timeout,
		Transport: oauth.Transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	err = json.Unmarshal(respBody, &authTokenResponse)
	if err != nil {
		return "", err
	}

	if authTokenResponse.ExpiresIn > 0 && authTokenResponse.AccessToken != "" {
		oauth.authToken = authTokenResponse
		oauth.lastRenewedTime = time.Now().UTC()
		go func() { notifyStatus <- true }()
	} else {
		go func() { notifyStatus <- false }()
	}

	return oauth.authToken.AccessToken, nil
}

func (oauth *Auth) UnaryClientInterceptor(c context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	ctx := metadata.AppendToOutgoingContext(c, "Authorization", fmt.Sprintf("Bearer %s", oauth.GetToken()))
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	err := invoker(ctx, method, req, reply, cc, opts...)
	cancel()

	code := status.Code(err)
	if code == codes.OK {
		return err
	}

	st := status.Convert(err)
	retryInfo := getRetryInfo(st)
	if !shouldRetry(code, retryInfo) {
		return err
	}

	backoff := oauth.RetrySettings.NewExponentialBackOff()
	backoff.Start()

	for {
		select {
		case <-backoff.Stop:
			return fmt.Errorf("all retries are exhauset, dropping traces")
		case <-backoff.C:
			if status.Code(err) == codes.Unauthenticated {
				// renew oauth token here before retry
				_, err := oauth.Renew()
				if err != nil {
					return err
				}
			}

			ctx := metadata.AppendToOutgoingContext(c, "Authorization", fmt.Sprintf("Bearer %s", oauth.GetToken()))
			ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
			err := invoker(ctx, method, req, reply, cc, opts...)
			cancel()
			code := status.Code(err)
			if code == codes.OK {
				return err
			}
			st := status.Convert(err)
			retryInfo := getRetryInfo(st)
			if !shouldRetry(code, retryInfo) {
				return err
			}
		}
	}
}

func getRetryInfo(status *status.Status) *errdetails.RetryInfo {
	for _, detail := range status.Details() {
		if t, ok := detail.(*errdetails.RetryInfo); ok {
			return t
		}
	}
	return nil
}

func shouldRetry(code codes.Code, retryInfo *errdetails.RetryInfo) bool {
	switch code {
	case codes.Canceled,
		codes.DeadlineExceeded,
		codes.Aborted,
		codes.OutOfRange,
		codes.Unavailable,
		codes.Unauthenticated,
		codes.DataLoss:
		// These are retryable errors.
		return true
	case codes.ResourceExhausted:
		// Retry only if RetryInfo was supplied by the server.
		// This indicates that the server can still recover from resource exhaustion.
		return retryInfo != nil
	}
	// Don't retry on any other code.
	return false
}
