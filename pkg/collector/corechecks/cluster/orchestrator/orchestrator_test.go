// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package orchestrator

import (
	"context"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors/inventory"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

func newCollectorBundle(chk *OrchestratorCheck) *CollectorBundle {
	bundle := &CollectorBundle{
		discoverCollectors: chk.orchestratorConfig.CollectorDiscoveryEnabled,
		check:              chk,
		inventory:          inventory.NewCollectorInventory(),
		runCfg: &collectors.CollectorRunConfig{
			APIClient:                   chk.apiClient,
			ClusterID:                   chk.clusterID,
			Config:                      chk.orchestratorConfig,
			MsgGroupRef:                 chk.groupID,
			OrchestratorInformerFactory: chk.orchestratorInformerFactory,
		},
		stopCh:              chk.stopCh,
		manifestBuffer:      NewManifestBuffer(chk),
		activatedCollectors: map[string]struct{}{},
	}
	bundle.importCollectorsFromInventory()
	bundle.prepareExtraSyncTimeout()
	return bundle
}

// TestOrchestratorCheckSafeReSchedule close simulates the check being unscheduled and rescheduled again
func TestOrchestratorCheckSafeReSchedule(t *testing.T) {
	var wg sync.WaitGroup

	client := fake.NewSimpleClientset()
	cl := &apiserver.APIClient{Cl: client}
	orchCheck := OrchestratorFactory().(*OrchestratorCheck)
	orchCheck.apiClient = cl
	orchCheck.orchestratorInformerFactory = orchCheck.getOrchestratorInformerFactory()

	bundle := newCollectorBundle(orchCheck)
	err := bundle.Initialize()
	assert.NoError(t, err)

	wg.Add(2)

	nodeInformer := orchCheck.orchestratorInformerFactory.InformerFactory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Println("hahah11")

			wg.Done()
		},
	})

	writeNode(t, client, "1")

	fmt.Println("be cancel")
	time.Sleep(10 * time.Millisecond)

	// getting rescheduled.
	orchCheck.Cancel()
	fmt.Println("af cancel")

	// This part is not optimal as the cancel closes a channel which gets propagated everywhere that might take some time.
	// If things are too fast the close is not getting propagated fast enough.
	// But even if we are too fast and don't catch that part it will not lead to a false positive
	time.Sleep(10 * time.Millisecond)

	bundle.runCfg.OrchestratorInformerFactory = orchCheck.getOrchestratorInformerFactory()
	if _, ok := <-bundle.stopCh; ok {
		close(bundle.stopCh)
	}
	bundle.stopCh = make(chan struct{})
	err = bundle.Initialize()
	assert.NoError(t, err)

	nodeInformer = bundle.runCfg.OrchestratorInformerFactory.InformerFactory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Println("hahah222")

			wg.Done()
		},
	})
	time.Sleep(10 * time.Millisecond)

	writeNode(t, client, "2")

	fmt.Println("waiting")
	wg.Wait()
}

func writeNode(t *testing.T, client *fake.Clientset, version string) {
	kubeN := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: version,
			UID:             types.UID("126430c6-5e57-11ea-91d5-42010a8400c6-" + version),
			Name:            "another-system-" + version,
		},
	}
	_, err := client.CoreV1().Nodes().Create(context.TODO(), &kubeN, metav1.CreateOptions{})
	assert.NoError(t, err)
}
