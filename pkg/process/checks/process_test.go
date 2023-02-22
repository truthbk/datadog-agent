// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"fmt"
	"regexp"
	"sort"
	"testing"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/gopsutil/cpu"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/process/procutil/mocks"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/tagger/local"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	metricsmock "github.com/DataDog/datadog-agent/pkg/util/containers/metrics/mock"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics/provider"
	"github.com/DataDog/datadog-agent/pkg/util/subscriptions"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

type ctrProc struct {
	ctrID   string
	pCounts int
}

func makeContainer(id string) *model.Container {
	return &model.Container{
		Id: id,
	}
}

func processCheckWithMockProbe(t *testing.T) (*ProcessCheck, *mocks.Probe) {
	t.Helper()
	probe := mocks.NewProbe(t)
	sysInfo := &model.SystemInfo{
		Cpus: []*model.CPUInfo{
			{CoreId: "1"},
			{CoreId: "2"},
			{CoreId: "3"},
			{CoreId: "4"},
		},
	}
	hostInfo := &HostInfo{
		SystemInfo: sysInfo,
	}

	return &ProcessCheck{
		probe:             probe,
		scrubber:          procutil.NewDefaultDataScrubber(),
		hostInfo:          hostInfo,
		containerProvider: mockContainerProvider(t),
		checkCount:        0,
		skipAmount:        2,
	}, probe
}

// TODO: create a centralized, easy way to mock this
func mockContainerProvider(t *testing.T) util.ContainerProvider {
	t.Helper()

	// Metrics provider
	metricsCollector := metricsmock.NewCollector("foo")
	metricsProvider := metricsmock.NewMetricsProvider()
	metricsProvider.RegisterConcreteCollector(provider.RuntimeNameContainerd, metricsCollector)
	metricsProvider.RegisterConcreteCollector(provider.RuntimeNameGarden, metricsCollector)

	// Workload meta + tagger
	metadataProvider := workloadmeta.NewMockStore()
	fakeTagger := local.NewFakeTagger()
	tagger.SetDefaultTagger(fakeTagger)
	defer tagger.SetDefaultTagger(nil)

	// Finally, container provider
	filter, err := containers.GetPauseContainerFilter()
	assert.NoError(t, err)
	return util.NewContainerProvider(metricsProvider, metadataProvider, filter)
}

func TestProcessCheckFirstRun(t *testing.T) {
	processCheck, probe := processCheckWithMockProbe(t)

	now := time.Now().Unix()
	proc1 := makeProcessWithCreateTime(1, "git clone google.com", now)
	proc2 := makeProcessWithCreateTime(2, "mine-bitcoins -all -x", now+1)
	proc3 := makeProcessWithCreateTime(3, "foo --version", now+2)
	proc4 := makeProcessWithCreateTime(4, "foo -bar -bim", now+3)
	proc5 := makeProcessWithCreateTime(5, "datadog-process-agent --cfgpath datadog.conf", now+2)
	processesByPid := map[int32]*procutil.Process{1: proc1, 2: proc2, 3: proc3, 4: proc4, 5: proc5}

	probe.On("ProcessesByPID", mock.Anything, mock.Anything).
		Return(processesByPid, nil)

	// The first run returns nothing because processes must be observed on two consecutive runs
	expected := CombinedRunResult{}

	actual, err := processCheck.run(0, false)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestProcessCheckSecondRun(t *testing.T) {
	processCheck, probe := processCheckWithMockProbe(t)

	now := time.Now().Unix()
	proc1 := makeProcessWithCreateTime(1, "git clone google.com", now)
	proc2 := makeProcessWithCreateTime(2, "mine-bitcoins -all -x", now+1)
	proc3 := makeProcessWithCreateTime(3, "foo --version", now+2)
	proc4 := makeProcessWithCreateTime(4, "foo -bar -bim", now+3)
	proc5 := makeProcessWithCreateTime(5, "datadog-process-agent --cfgpath datadog.conf", now+2)
	processesByPid := map[int32]*procutil.Process{1: proc1, 2: proc2, 3: proc3, 4: proc4, 5: proc5}

	probe.On("ProcessesByPID", mock.Anything, mock.Anything).
		Return(processesByPid, nil)

	// The first run returns nothing because processes must be observed on two consecutive runs
	first, err := processCheck.run(0, false)
	require.NoError(t, err)
	assert.Equal(t, CombinedRunResult{}, first)

	expected := []model.MessageBody{
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc1)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc2)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc3)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc4)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc5)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
	}
	actual, err := processCheck.run(0, false)
	require.NoError(t, err)
	assert.ElementsMatch(t, expected, actual.Payloads()) // ordering is not guaranteed
	assert.Nil(t, actual.RealtimePayloads())
}

func TestProcessCheckWithRealtime(t *testing.T) {
	processCheck, probe := processCheckWithMockProbe(t)

	proc1 := makeProcess(1, "git clone google.com")
	proc2 := makeProcess(2, "mine-bitcoins -all -x")
	proc3 := makeProcess(3, "foo --version")
	proc4 := makeProcess(4, "foo -bar -bim")
	proc5 := makeProcess(5, "datadog-process-agent --cfgpath datadog.conf")
	processesByPid := map[int32]*procutil.Process{1: proc1, 2: proc2, 3: proc3, 4: proc4, 5: proc5}

	probe.On("ProcessesByPID", mock.Anything, mock.Anything).
		Return(processesByPid, nil)

	// The first run returns nothing because processes must be observed on two consecutive runs
	first, err := processCheck.run(0, true)
	require.NoError(t, err)
	assert.Equal(t, CombinedRunResult{}, first)

	expectedProcs := []model.MessageBody{
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc1)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc2)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc3)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc4)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc5)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
	}

	expectedStats := makeProcessStatModels(t, proc1, proc2, proc3, proc4, proc5)
	actual, err := processCheck.run(0, true)
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedProcs, actual.Payloads()) // ordering is not guaranteed
	require.Len(t, actual.RealtimePayloads(), 1)
	rt := actual.RealtimePayloads()[0].(*model.CollectorRealTime)
	assert.ElementsMatch(t, expectedStats, rt.Stats)
	assert.Equal(t, int32(1), rt.GroupSize)
	assert.Equal(t, int32(len(processCheck.hostInfo.SystemInfo.Cpus)), rt.NumCpus)
}

func TestOnlyEnvConfigArgsScrubbingEnabled(t *testing.T) {
	_ = ddconfig.Mock(t)

	t.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	scrubber := procutil.NewDefaultDataScrubber()
	initScrubber(scrubber)

	assert.True(t, scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=********", "consul_token", "********", "--dd_api_key=********"},
		},
	}

	for i := range cases {
		cases[i].cmdline, _ = scrubber.ScrubCommand(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
}

func TestOnlyEnvConfigArgsScrubbingDisabled(t *testing.T) {
	_ = ddconfig.Mock(t)

	t.Setenv("DD_SCRUB_ARGS", "false")
	t.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	scrubber := procutil.NewDefaultDataScrubber()
	initScrubber(scrubber)

	assert.False(t, scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
		},
	}

	for i := range cases {
		fp := &procutil.Process{Cmdline: cases[i].cmdline}
		cases[i].cmdline = scrubber.ScrubProcessCommand(fp)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
}

func TestDisallowList(t *testing.T) {
	testDisallowList := []string{
		"^getty",
		"^acpid",
		"^atd",
		"^upstart-udev-bridge",
		"^upstart-socket-bridge",
		"^upstart-file-bridge",
		"^dhclient",
		"^dhclient3",
		"^rpc",
		"^dbus-daemon",
		"udevd",
		"^/sbin/",
		"^/usr/sbin/",
		"^/var/ossec/bin/ossec",
		"^rsyslogd",
		"^whoopsie$",
		"^cron$",
		"^CRON$",
		"^/usr/lib/postfix/master$",
		"^qmgr",
		"^pickup",
		"^sleep",
		"^/lib/systemd/systemd-logind$",
		"^/usr/local/bin/goshe dnsmasq$",
	}
	disallowList := make([]*regexp.Regexp, 0, len(testDisallowList))
	for _, b := range testDisallowList {
		r, err := regexp.Compile(b)
		if err == nil {
			disallowList = append(disallowList, r)
		}
	}
	cases := []struct {
		cmdline        []string
		disallowListed bool
	}{
		{[]string{"getty", "-foo", "-bar"}, true},
		{[]string{"rpcbind", "-x"}, true},
		{[]string{"my-rpc-app", "-config foo.ini"}, false},
		{[]string{"rpc.statd", "-L"}, true},
		{[]string{"/usr/sbin/irqbalance"}, true},
	}

	for _, c := range cases {
		assert.Equal(t, c.disallowListed, isDisallowListed(c.cmdline, disallowList),
			fmt.Sprintf("Case %v failed", c))
	}
}

func TestConnRates(t *testing.T) {
	p := &ProcessCheck{}

	p.initConnRates()

	var transmitter subscriptions.Transmitter[ProcessConnRates]
	transmitter.Chs = append(transmitter.Chs, p.connRatesReceiver.Ch)

	rates := ProcessConnRates{
		1: &model.ProcessNetworks{},
	}
	transmitter.Notify(rates)

	close(p.connRatesReceiver.Ch)

	assert.Eventually(t, func() bool { return p.getLastConnRates() != nil }, 10*time.Second, time.Millisecond)
	assert.Equal(t, rates, p.getLastConnRates())
}

func TestProcessCheckHints(t *testing.T) {
	processCheck, probe := processCheckWithMockProbe(t)

	now := time.Now().Unix()
	proc1 := makeProcessWithCreateTime(1, "git clone google.com", now)
	processesByPid := map[int32]*procutil.Process{1: proc1}

	probe.On("ProcessesByPID", mock.Anything, mock.Anything).
		Return(processesByPid, nil)

	// The first run returns nothing because processes must be observed on two consecutive runs
	first, err := processCheck.run(0, false)
	require.NoError(t, err)
	assert.Equal(t, CombinedRunResult{}, first)

	expected := []model.MessageBody{
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc1)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
	}
	actual, err := processCheck.run(0, false)
	require.NoError(t, err)
	assert.ElementsMatch(t, expected, actual.Payloads()) // ordering is not guaranteed
	assert.Nil(t, actual.RealtimePayloads())

	expectedUnspecified := []model.MessageBody{
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc1)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0},
		},
	}

	actual, err = processCheck.run(0, false)
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedUnspecified, actual.Payloads()) // ordering is not guaranteed
	assert.Nil(t, actual.RealtimePayloads())

	expectedDiscovery := []model.MessageBody{
		&model.CollectorProc{
			Processes: []*model.Process{makeProcessModel(t, proc1)},
			GroupSize: int32(len(processesByPid)),
			Info:      processCheck.hostInfo.SystemInfo,
			Hints:     &model.CollectorProc_HintMask{HintMask: 0b1},
		},
	}

	actual, err = processCheck.run(0, false)
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedDiscovery, actual.Payloads()) // ordering is not guaranteed
}

// TestBasicProcessMessages tests basic cases for creating payloads by hard-coded scenarios
func TestBasicProcessMessages(t *testing.T) {
	const maxBatchBytes = 1000000
	p := []*procutil.Process{
		makeProcess(1, "git clone google.com"),
		makeProcess(2, "mine-bitcoins -all -x"),
		makeProcess(3, "foo --version"),
		makeProcess(4, "foo -bar -bim"),
		makeProcess(5, "datadog-process-agent --cfgpath datadog.conf"),
	}
	c := []*model.Container{
		makeContainer("foo"),
		makeContainer("bar"),
	}
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}
	sysInfo := &model.SystemInfo{}
	hostInfo := &HostInfo{SystemInfo: sysInfo}

	for i, tc := range []struct {
		testName           string
		processes          map[int32]*procutil.Process
		containers         []*model.Container
		pidToCid           map[int]string
		maxSize            int
		disallowList       []string
		expectedChunks     int
		expectedProcs      int
		expectedContainers int
	}{
		{
			testName:           "no containers",
			processes:          map[int32]*procutil.Process{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:            2,
			containers:         []*model.Container{},
			pidToCid:           nil,
			disallowList:       []string{},
			expectedChunks:     2,
			expectedProcs:      3,
			expectedContainers: 0,
		},
		{
			testName:           "container processes",
			processes:          map[int32]*procutil.Process{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:            2,
			containers:         []*model.Container{c[0]},
			pidToCid:           map[int]string{1: "foo", 2: "foo"},
			disallowList:       []string{},
			expectedChunks:     2,
			expectedProcs:      3,
			expectedContainers: 1,
		},
		{
			testName:           "container processes separate",
			processes:          map[int32]*procutil.Process{p[2].Pid: p[2], p[3].Pid: p[3], p[4].Pid: p[4]},
			maxSize:            1,
			containers:         []*model.Container{c[1]},
			pidToCid:           map[int]string{3: "bar"},
			disallowList:       []string{},
			expectedChunks:     3,
			expectedProcs:      3,
			expectedContainers: 1,
		},
		{
			testName:           "no non-container processes",
			processes:          map[int32]*procutil.Process{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:            2,
			containers:         []*model.Container{c[0], c[1]},
			pidToCid:           map[int]string{1: "foo", 2: "foo", 3: "bar"},
			disallowList:       []string{},
			expectedChunks:     2,
			expectedProcs:      3,
			expectedContainers: 2,
		},
		{
			testName:           "foo processes skipped",
			processes:          map[int32]*procutil.Process{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:            2,
			containers:         []*model.Container{c[1]},
			pidToCid:           map[int]string{3: "bar"},
			disallowList:       []string{"foo"},
			expectedChunks:     1,
			expectedProcs:      2,
			expectedContainers: 1,
		},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			disallowList := make([]*regexp.Regexp, 0, len(tc.disallowList))
			for _, s := range tc.disallowList {
				disallowList = append(disallowList, regexp.MustCompile(s))
			}

			procs := fmtProcesses(procutil.NewDefaultDataScrubber(), disallowList, tc.processes, tc.processes, tc.pidToCid, syst2, syst1, lastRun, nil)
			messages, totalProcs, totalContainers := createProcCtrMessages(hostInfo, procs, tc.containers, tc.maxSize, maxBatchBytes, int32(i), "nid", 0)

			assert.Equal(t, tc.expectedChunks, len(messages))

			assert.Equal(t, tc.expectedProcs, totalProcs)
			assert.Equal(t, tc.expectedContainers, totalContainers)
		})
	}
}

// TestContainerProcessChunking generates processes and containers and tests that they are properly chunked
func TestContainerProcessChunking(t *testing.T) {
	const maxBatchBytes = 1000000

	for i, tc := range []struct {
		testName                            string
		ctrProcs                            []ctrProc
		expectedBatches                     []map[string]int
		expectedCtrCount, expectedProcCount int
		maxSize                             int
	}{
		{
			testName: "no containers",
			ctrProcs: []ctrProc{
				{ctrID: "", pCounts: 3},
			},
			expectedBatches: []map[string]int{
				{"": 3},
			},
			expectedProcCount: 3,
			maxSize:           10,
		},
		{
			testName: "non-container processes are chunked",
			ctrProcs: []ctrProc{
				{ctrID: "", pCounts: 8},
			},
			expectedBatches: []map[string]int{
				{"": 2},
				{"": 2},
				{"": 2},
				{"": 2},
			},
			expectedProcCount: 8,
			maxSize:           2,
		},
		{
			testName: "remaining container processes are batched",
			ctrProcs: []ctrProc{
				{ctrID: "1", pCounts: 100},
				{ctrID: "2", pCounts: 20},
				{ctrID: "3", pCounts: 30},
			},
			expectedBatches: []map[string]int{
				{"1": 50},
				{"1": 50},
				{"2": 20, "3": 30},
			},
			expectedCtrCount:  3,
			expectedProcCount: 150,
			maxSize:           50,
		},
		{
			testName: "non-container and container process are batched together",
			ctrProcs: []ctrProc{
				{ctrID: "", pCounts: 3},
				{ctrID: "1", pCounts: 4},
			},
			expectedBatches: []map[string]int{
				{"": 3, "1": 4},
			},
			expectedCtrCount:  1,
			expectedProcCount: 7,
			maxSize:           10,
		},
		{
			testName: "container process batched to size",
			ctrProcs: []ctrProc{
				{ctrID: "1", pCounts: 5},
				{ctrID: "2", pCounts: 4},
				{ctrID: "3", pCounts: 1},
				{ctrID: "4", pCounts: 1},
				{ctrID: "5", pCounts: 4},
				{ctrID: "6", pCounts: 2},
				{ctrID: "7", pCounts: 9},
			},
			expectedBatches: []map[string]int{
				{"1": 5, "2": 4, "3": 1},
				{"4": 1, "5": 4, "6": 2, "7": 3},
				{"7": 6},
			},
			expectedCtrCount:  7,
			expectedProcCount: 26,
			maxSize:           10,
		},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			procs, ctrs, pidToCid := generateCtrProcs(tc.ctrProcs)
			procsByPid := procsToHash(procs)

			lastRun := time.Now().Add(-5 * time.Second)
			syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}
			sysInfo := &model.SystemInfo{}
			hostInfo := &HostInfo{SystemInfo: sysInfo}

			processes := fmtProcesses(procutil.NewDefaultDataScrubber(), nil, procsByPid, procsByPid, pidToCid, syst2, syst1, lastRun, nil)
			messages, totalProcs, totalContainers := createProcCtrMessages(hostInfo, processes, ctrs, tc.maxSize, maxBatchBytes, int32(i), "nid", 0)

			assert.Equal(t, tc.expectedProcCount, totalProcs)
			assert.Equal(t, tc.expectedCtrCount, totalContainers)

			// sort and verify messages
			sortMsgs(messages)
			verifyBatchedMsgs(t, hostInfo, tc.expectedBatches, messages)
		})
	}
}

// sortMsgs sorts the CollectorProc messages so they can be validated deterministically
func sortMsgs(m []model.MessageBody) {
	// sort the processes and containers of each message
	for i := range m {
		payload := m[i].(*model.CollectorProc)
		sort.SliceStable(payload.Containers, func(i, j int) bool {
			return payload.Containers[i].Id < payload.Containers[j].Id
		})
		sort.SliceStable(payload.Processes, func(i, j int) bool {
			return payload.Processes[i].Pid < payload.Processes[j].Pid
		})
	}

	// sort all the messages by containers
	sort.SliceStable(m, func(i, j int) bool {
		cI := m[i].(*model.CollectorProc).Containers
		cJ := m[j].(*model.CollectorProc).Containers

		if cI == nil {
			return true
		}
		if cJ == nil {
			return false
		}

		return cI[0].Id <= cJ[0].Id
	})
}

func verifyBatchedMsgs(t *testing.T, hostInfo *HostInfo, expected []map[string]int, msgs []model.MessageBody) {
	assert := assert.New(t)

	assert.Equal(len(expected), len(msgs), "Number of messages created")

	for i, msg := range msgs {
		payload := msg.(*model.CollectorProc)

		assert.Equal(hostInfo.ContainerHostType, payload.ContainerHostType)

		actualCtrPIDCounts := map[string]int{}

		// verify number of processes for each container
		for _, proc := range payload.Processes {
			actualCtrPIDCounts[proc.ContainerId]++
		}

		assert.EqualValues(expected[i], actualCtrPIDCounts)
	}
}

// generateCtrProcs generates groups of processes for linking with containers
func generateCtrProcs(ctrProcs []ctrProc) ([]*procutil.Process, []*model.Container, map[int]string) {
	var procs []*procutil.Process
	var ctrs []*model.Container
	pidToCid := make(map[int]string)
	pid := 1

	for _, ctrProc := range ctrProcs {
		ctr := makeContainer(ctrProc.ctrID)
		if ctr.Id != emptyCtrID {
			ctrs = append(ctrs, ctr)
		}

		for i := 0; i < ctrProc.pCounts; i++ {
			proc := makeProcess(int32(pid), fmt.Sprintf("cmd %d", pid))
			procs = append(procs, proc)
			pidToCid[pid] = ctr.Id
			pid++
		}
	}
	return procs, ctrs, pidToCid
}

func BenchmarkProcessCheck(b *testing.B) {
	processCheck, probe := processCheckWithMockProbe(&testing.T{})

	now := time.Now().Unix()
	proc1 := makeProcessWithCreateTime(1, "git clone google.com", now)
	proc2 := makeProcessWithCreateTime(2, "mine-bitcoins -all -x", now+1)
	proc3 := makeProcessWithCreateTime(3, "foo --version", now+2)
	proc4 := makeProcessWithCreateTime(4, "foo -bar -bim", now+3)
	proc5 := makeProcessWithCreateTime(5, "datadog-process-agent --cfgpath datadog.conf", now+2)
	processesByPid := map[int32]*procutil.Process{1: proc1, 2: proc2, 3: proc3, 4: proc4, 5: proc5}

	probe.On("ProcessesByPID", mock.Anything, mock.Anything).Return(processesByPid, nil)

	for n := 0; n < b.N; n++ {
		_, err := processCheck.run(0, false)
		require.NoError(b, err)
	}
}
