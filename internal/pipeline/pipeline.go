// Package pipeline 负责批量编排：并发识别但严格保序，并保证"进 N 条出 N 条"。
//
// 单条识别是纯 CPU 的内存操作（规则已预编译），因此不需要对每条加超时;
// 但为了防御未来规则引入的病态正则或数据，这里对每条做 panic 隔离，
// 一条出问题只降级成 unknown，绝不影响整批和进程。
package pipeline

import (
	"runtime"
	"sync"

	"bannerfp/internal/engine"
	"bannerfp/internal/model"
)

const maxWorkers = 32

// Run 识别一批输入，返回等长、同序的结果。
func Run(eng *engine.Engine, items []model.ScanInput) []model.Result {
	results := make([]model.Result, len(items))
	if len(items) == 0 {
		return results
	}

	workers := runtime.GOMAXPROCS(0) * 2
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers > len(items) {
		workers = len(items)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = safeIdentify(eng, items[i])
			}
		}()
	}
	for i := range items {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func safeIdentify(eng *engine.Engine, in model.ScanInput) (res model.Result) {
	defer func() {
		if r := recover(); r != nil {
			res = model.Result{IP: in.IP, Port: in.Port, Protocol: model.ProtocolUnknown}
		}
	}()
	return eng.Identify(in)
}
