package transmission

import "sync"

var (
	notifyStatus        chan bool     = make(chan bool)
	DefaultAvailability *Availability = &Availability{
		online: false,
		mut:    sync.RWMutex{},
	}
)

func init() {
	go func() {
		for {
			select {
			case status := <-notifyStatus:
				DefaultAvailability.Set(status)
			}
		}
	}()
}

type Availability struct {
	online bool
	mut    sync.RWMutex
}

func (a *Availability) Status() bool {
	a.mut.RLock()
	defer a.mut.RUnlock()

	return a.online
}

func (a *Availability) Set(status bool) {
	a.mut.Lock()
	defer a.mut.Unlock()

	a.online = status
}
