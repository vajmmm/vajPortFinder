package vars

import "sync"

var (
	ThreadNum = 10
	Result    *sync.Map
)

func init() {
	Result = &sync.Map{}
}
