/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package placement

import (
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/apache/yunikorn-core/pkg/common/configs"
	"github.com/apache/yunikorn-core/pkg/common/security"
	"github.com/apache/yunikorn-core/pkg/handler"
	"github.com/apache/yunikorn-core/pkg/scheduler/objects"
	"github.com/apache/yunikorn-scheduler-interface/lib/go/si"
)

// Create the structure for the parent rule tests
// shared by a number of rule tests
const confParentChild = `
partitions:
  - name: default
    queues:
      - name: testchild
      - name: testparent
        parent: true
`
const nameParentChild = "root.testparentnew.testchild"

// Create the structure for the test
const confTestQueue = `
partitions:
  - name: default
    queues:
      - name: testqueue
      - name: testparent
        queues:
          - name: testchild
`

var root *objects.Queue

// Mocked up function to mimic the partition getQueue function
// Since this is for test only we do not check inputs etc.
func queueFunc(name string) *objects.Queue {
	queue := root
	part := strings.Split(strings.ToLower(name), configs.DOT)
	// walk over the parts going down towards the requested queue
	for i := 1; i < len(part); i++ {
		// if child not found break out and return
		if queue = queue.GetChildQueue(part[i]); queue == nil {
			break
		}
	}
	return queue
}

// Create a queue structure for the placement without the need to create a partition
func initQueueStructure(data []byte) error {
	conf, err := configs.LoadSchedulerConfigFromByteArray(data)
	if err != nil {
		return err
	}
	rootConf := conf.Partitions[0].Queues[0]
	root, err = objects.NewConfiguredQueue(rootConf, nil, false)
	if err != nil {
		return err
	}
	return addQueue(rootConf.Queues, root)
}

func addQueue(conf []configs.QueueConfig, parent *objects.Queue) error {
	for _, queueConf := range conf {
		thisQueue, err := objects.NewConfiguredQueue(queueConf, parent, false)
		if err != nil {
			return err
		}
		// recursive create the queues below
		if len(queueConf.Queues) > 0 {
			err = addQueue(queueConf.Queues, thisQueue)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func newApplication(appID, partition, queueName string, ugi security.UserGroup, tags map[string]string, eventHandler handler.EventHandler, rmID string) *objects.Application {
	siApp := &si.AddApplicationRequest{
		ApplicationID: appID,
		QueueName:     queueName,
		PartitionName: partition,
		Tags:          tags,
	}
	return objects.NewApplication(siApp, ugi, eventHandler, rmID)
}

func TestTestRulePlace(t *testing.T) {
	// Create the structure for the test
	data := `
partitions:
  - name: default
    queues:
      - name: testparent
        queues:
          - name: testchild
`
	err := initQueueStructure([]byte(data))
	assert.NilError(t, err, "setting up the queue config failed")

	tags := make(map[string]string)
	user := security.UserGroup{
		User:   "test",
		Groups: []string{},
	}

	conf := configs.PlacementRule{
		Name: "test",
	}
	var pr rule
	pr, err = newRule(conf)
	if err != nil || pr == nil {
		t.Errorf("test rule create failed, err %v", err)
	}
	appInfo := newApplication("app1", "default", "testchild", user, tags, nil, "")
	var queue string
	queue, err = pr.placeApplication(appInfo, queueFunc)
	if queue != "testchild" || err != nil {
		t.Errorf("test rule placed app in incorrect queue '%s', err %v", queue, err)
	}

	// invalid queueName
	appInfo = newApplication("app1", "default", "test$child", user, tags, nil, "")
	queue, err = pr.placeApplication(appInfo, queueFunc)
	if queue != "" || err == nil {
		t.Errorf("invalid queueName should got empty queueName")
	}
}
