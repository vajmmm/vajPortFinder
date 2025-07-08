package scanner

import (
	"portfinder/util"
	"portfinder/vars"
	"sync"
)

func AssigningTasks(tasks []map[string]int, scanner Scanner) {
	scanBatch := len(tasks) / vars.ThreadNum
	for i := 0; i < scanBatch; i++ {
		curTask := tasks[vars.ThreadNum*i : vars.ThreadNum*(i+1)]
		runTask(curTask, scanner)
	}

	if len(tasks)%vars.ThreadNum > 0 {
		lastTask := tasks[vars.ThreadNum*scanBatch:]
		runTask(lastTask, scanner)
	}
}

func runTask(tasks []map[string]int, scanner Scanner) {
	wg := &sync.WaitGroup{}
	taskChan := make(chan map[string]int, vars.ThreadNum*2)

	for i := 0; i < vars.ThreadNum; i++ {
		go scan(taskChan, wg, scanner)
	}
	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()
}

func scan(taskChan chan map[string]int, wg *sync.WaitGroup, scanner Scanner) {
	id := 0
	for task := range taskChan {
		for ip, port := range task {
			go func(id int, ip string, port int) {
				err := scanner.Connect(id, ip, port)

				if err == nil {
					_ = util.SaveResult(ip, port, err)
				}
				wg.Done()
			}(id, ip, port)
			id++
		}
	}
}
