package transmission

import (
	"math/rand"
	"time"
)

const (
	DefaultInitialInterval     = 500 * time.Millisecond
	DefaultRandomizationFactor = 0.5
	DefaultMultiplier          = 1.5
	DefaultMaxInterval         = 60 * time.Second
	DefaultMaxElapsedTime      = 15 * time.Minute
)

// RetrySettings defines configuration for retrying. currently supported strategy is exponential backoff
type RetrySettings struct {
	// InitialInterval the time to wait after the first failure before retrying.
	InitialInterval time.Duration
	// RandomizationFactor is a random factor used to calculate next backoff
	// Randomized interval = RetryInterval * (1 ± RandomizationFactor)
	RandomizationFactor float64
	// Multiplier is the value multiplied by the backoff interval bounds
	Multiplier float64
	// MaxInterval is the upper bound on backoff interval. Once this value is reached, the delay between
	// consecutive retries will always be `MaxInterval`.
	MaxInterval time.Duration
	// MaxElapsedTime is the maximum amount of time (including retries) spent trying to send a request.
	// Once this value is reached, the data is discarded.
	MaxElapsedTime time.Duration
}

// NewDefaultRetrySettings returns the default settings for RetrySettings.
func NewDefaultRetrySettings() *RetrySettings {
	return &RetrySettings{
		InitialInterval:     DefaultInitialInterval,
		RandomizationFactor: DefaultRandomizationFactor,
		Multiplier:          DefaultMultiplier,
		MaxInterval:         DefaultMaxInterval,
		MaxElapsedTime:      DefaultMaxElapsedTime,
	}
}

func (r *RetrySettings) NewExponentialBackOff() *ExponentialBackOff {
	return &ExponentialBackOff{
		retrySettings: r,
		startedAt:     time.Now().UTC(),
		Stop:          make(chan struct{}),
		C:             make(chan struct{}),
	}
}

type ExponentialBackOff struct {
	retrySettings *RetrySettings
	startedAt     time.Time

	Stop chan struct{}
	C    chan struct{}
}

func (e *ExponentialBackOff) Start() {
	go func() {
		// set timer to MaxElapsedTime to terminate further requests
		done := time.NewTimer(e.retrySettings.MaxElapsedTime)

		presentInterval := e.retrySettings.InitialInterval
		// initialize ticker to InitialInterval
		tick := time.NewTicker(e.retrySettings.InitialInterval)
		for {
			select {
			case <-done.C:
				return
			case <-tick.C:
				// send retry event since the timer is up
				e.C <- struct{}{}

				// calculate the next retry time
				elapsed := e.GetElapseTime()
				next := getRandomValueFromInterval(e.retrySettings.RandomizationFactor, rand.Float64(), presentInterval)
				// Check for overflow, if overflow is detected set the present interval to the max interval.
				if float64(presentInterval) >= float64(e.retrySettings.MaxInterval)/e.retrySettings.Multiplier {
					presentInterval = e.retrySettings.MaxInterval
				} else {
					presentInterval = time.Duration(float64(presentInterval) * e.retrySettings.Multiplier)
				}
				if e.retrySettings.MaxElapsedTime != 0 && elapsed+next > e.retrySettings.MaxElapsedTime {
					e.Stop <- struct{}{}
					return
				}

				// reset the ticker to check for the present interval
				tick.Reset(presentInterval)
			}
		}
	}()
}

func (e *ExponentialBackOff) GetElapseTime() time.Duration {
	return time.Now().UTC().Sub(e.startedAt)
}

// Returns a random value from the following interval:
//
//	[currentInterval - randomizationFactor * currentInterval, currentInterval + randomizationFactor * currentInterval].
func getRandomValueFromInterval(randomizationFactor, random float64, currentInterval time.Duration) time.Duration {
	if randomizationFactor == 0 {
		return currentInterval // make sure no randomness is used when randomizationFactor is 0.
	}
	var delta = randomizationFactor * float64(currentInterval)
	var minInterval = float64(currentInterval) - delta
	var maxInterval = float64(currentInterval) + delta

	// Get a random value from the range [minInterval, maxInterval].
	// The formula used below has a +1 because if the minInterval is 1 and the maxInterval is 3 then
	// we want a 33% chance for selecting either 1, 2 or 3.
	return time.Duration(minInterval + (random * (maxInterval - minInterval + 1)))
}
