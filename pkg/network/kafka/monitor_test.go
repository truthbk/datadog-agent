// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package kafka

import (
	"context"
	"fmt"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/http/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
)

func skipTestIfKernelNotSupported(t *testing.T) {
	currKernelVersion, err := kernel.HostVersion()
	require.NoError(t, err)
	if currKernelVersion < MinimumKernelVersion {
		t.Skip(fmt.Sprintf("Kafka feature not available on pre %s kernels", MinimumKernelVersion.String()))
	}
}

func setUpKafkaDocker(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	envs := []string{
		fmt.Sprintf("KAFKA_ADDR=%s", "127.0.0.1"),
		"KAFKA_PORT=9092",
	}
	dir, _ := testutil.CurDir()
	cmd := exec.Command("docker", "compose", "-f", dir+"/testdata/docker-compose.yml", "up")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(cmd.Env, envs...)
	go func() {
		if err := cmd.Run(); err != nil {
			fmt.Println("error", err)
		}
	}()

	t.Cleanup(func() {
		c := exec.Command("docker-compose", "-f", dir+"/testdata/docker-compose.yml", "down", "--remove-orphans")
		c.Stdout = os.Stdout
		c.Stderr = os.Stdout
		c.Env = append(c.Env, envs...)
		_ = c.Run()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	require.NoError(t, waitForKafka(ctx, fmt.Sprintf("%s:9092", "127.0.0.1")))
	cancel()
}

func waitForKafka(ctx context.Context, zookeeperAddr string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if tryConnectingKafka(zookeeperAddr) {
				return nil
			}
			time.Sleep(time.Second)
			continue
		}
	}
}

func tryConnectingKafka(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// This test loads the Kafka binary, produce and fetch kafka messages and verifies that we capture them
func TestSanity(t *testing.T) {
	t.Skip("We cannot set up a Kafka cluster in the test environment because of dockerhub rate limiter")
	skipTestIfKernelNotSupported(t)

	cfg := config.New()
	cfg.BPFDebug = true
	monitor, err := NewMonitor(cfg)
	require.NoError(t, err)
	err = monitor.Start()
	require.NoError(t, err)
	defer monitor.Stop()

	// Assuming a kafka cluster is up and running

	// to produce/consume messages
	topic := strings.Repeat("t", 50)
	partition := 0

	myDialer := kafka.DefaultDialer
	myDialer.ClientID = "test-client-id"

	conn, err := myDialer.DialLeader(context.Background(), "tcp", "127.0.0.1:9092", topic, partition)
	require.NoError(t, err)

	err = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	require.NoError(t, err)
	_, err = conn.WriteMessages(
		kafka.Message{Value: []byte("one!")},
	)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{"127.0.0.1:9092"},
		Topic:     topic,
		Partition: 0,
		MinBytes:  10e3, // 10KB
		MaxBytes:  10e6, // 10MB
	})
	err = r.SetOffset(0)
	require.NoError(t, err)

	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	for {
		m, err := r.ReadMessage(ctxTimeout)
		if err != nil {
			break
		}
		fmt.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))
	}
	require.NoError(t, r.Close())

	kafkaStats := monitor.GetKafkaStats()
	// We expect 2 occurrences for each connection as we are working with a docker for now
	require.Equal(t, 4, len(kafkaStats))
	for _, kafkaStat := range kafkaStats {
		// When the ctxTimeout is configured with 10 seconds, we get 2 fetches from this client
		kafkaStatIsOK := kafkaStat.Data[ProduceAPIKey].Count == 1 || kafkaStat.Data[FetchAPIKey].Count == 2
		// TODO: need to add the kafka_seen_before so we won't get too much requests
		require.True(t, kafkaStatIsOK)
	}
}

// This test will help us identify if there is any verifier problems while loading the Kafka binary in the CI environment
func TestLoadKafkaBinary(t *testing.T) {
	skipTestIfKernelNotSupported(t)

	cfg := config.New()
	monitor, err := NewMonitor(cfg)
	require.NoError(t, err)
	err = monitor.Start()
	require.NoError(t, err)
	defer monitor.Stop()
}

// This test will help us identify if there is any verifier problems while loading the Kafka binary in the CI environment
func TestLoadKafkaDebugBinary(t *testing.T) {
	skipTestIfKernelNotSupported(t)

	cfg := config.New()
	cfg.BPFDebug = true
	monitor, err := NewMonitor(cfg)
	require.NoError(t, err)
	err = monitor.Start()
	require.NoError(t, err)
	defer monitor.Stop()
}

func TestVersionsFranz(t *testing.T) {
	skipTestIfKernelNotSupported(t)

	//setUpKafkaDocker(t)

	topicName := "franz-kafka"
	seeds := []string{"localhost:9092"}
	// One client can both produce and consume!
	// Consuming can either be direct (no consumer group), or through a group. Below, we use a group.
	client, err := kgo.NewClient(
		kgo.SeedBrokers(seeds...),
		kgo.ConsumerGroup("my-group-identifier"),
		kgo.ConsumeTopics(topicName),
		kgo.TransactionalID("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
		kgo.DefaultProduceTopic(topicName),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Create the topic
	adminClient := kadm.NewClient(client)
	_, err = adminClient.CreateTopics(ctx, 1, 1, nil, topicName)
	require.NoError(t, err)

	// 1.) Producing a message

	//record := &kgo.Record{Topic: topicName, Value: []byte("HelloKafka!")}
	//if err := client.ProduceSync(ctx, record).FirstErr(); err != nil {
	//	fmt.Printf("record had a produce error while synchronously producing: %v\n", err)
	//}

	require.NoError(t, client.BeginTransaction())

	// Write some messages in the transaction.
	if err := produceRecords(ctx, client, 0); err != nil {
		rollback(ctx, client)
		require.NoError(t, err, "error producing message: %v", err)
	}

	// Flush all of the buffered messages.
	//
	// Flush only returns an error if the context was canceled, and
	// it is highly not recommended to cancel the context.
	require.NoError(t, client.Flush(ctx), "flush was killed due to context cancelation")

	// Attempt to commit the transaction and explicitly abort if the
	// commit was not attempted.
	switch err := client.EndTransaction(ctx, kgo.TryCommit); err {
	case nil:
	case kerr.OperationNotAttempted:
		rollback(ctx, client)
	default:
		fmt.Printf("error committing transaction: %v\n", err)
	}

	// 2.) Consuming messages from a topic
	for {
		fetches := client.PollFetches(ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			// All errors are retried internally when fetching, but non-retriable errors are
			// returned from polls so that users can notice and take action.
			panic(fmt.Sprint(errs))
		}

		// We can iterate through a record iterator...
		iter := fetches.RecordIter()
		for !iter.Done() {
			record := iter.Next()
			fmt.Println(string(record.Value), "from an iterator!")
		}

		// or a callback function.
		fetches.EachPartition(func(p kgo.FetchTopicPartition) {
			for _, record := range p.Records {
				fmt.Println(string(record.Value), "from range inside a callback!")
			}

			// We can even use a second callback!
			p.EachRecord(func(record *kgo.Record) {
				fmt.Println(string(record.Value), "from a second callback!")
			})
		})
	}
}

// Records are produced synchronously in order to demonstrate that a consumer
// using the ReadCommitted isolation level will not consume any records until
// the transaction is committed.
func produceRecords(ctx context.Context, client *kgo.Client, batch int) error {
	for i := 0; i < 10; i++ {
		message := fmt.Sprintf("batch %d record %d\n", batch, i)
		if err := client.ProduceSync(ctx, kgo.StringRecord(message)).FirstErr(); err != nil {
			return err
		}
	}
	return nil
}

func rollback(ctx context.Context, client *kgo.Client) {
	if err := client.AbortBufferedRecords(ctx); err != nil {
		fmt.Printf("error aborting buffered records: %v\n", err) // this only happens if ctx is canceled
		return
	}
	if err := client.EndTransaction(ctx, kgo.TryAbort); err != nil {
		fmt.Printf("error rolling back transaction: %v\n", err)
		return
	}
	fmt.Println("transaction rolled back")
}
