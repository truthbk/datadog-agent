// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package patch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/common"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	admissionEnabledLabelKey      = "admission.datadoghq.com/enabled"
	libVersionAnnotationKeyFormat = "admission.datadoghq.com/%s-lib.version"
	libConfigAnnotationKeyFormat  = "admission.datadoghq.com/%s-lib.config"
)

type deployPatcher struct {
	k8sClient     kubernetes.Interface
	isLeaderFunc  func() bool
	requestsQueue chan patchRequest
}

func newDeployPatcher(k8sClient kubernetes.Interface, isLeaderFunc func() bool, rp requestProvider) *deployPatcher {
	return &deployPatcher{
		k8sClient:     k8sClient,
		isLeaderFunc:  isLeaderFunc,
		requestsQueue: rp.subscribe("Deployment"),
	}
}

func (dp *deployPatcher) start(stopCh <-chan struct{}) {
	for {
		select {
		case req := <-dp.requestsQueue:
			if err := dp.patch(req); err != nil {
				log.Error(err.Error())
			}
		case <-stopCh:
			log.Info("Shutting down deploy patcher")
			return
		}
	}
}

func (dp *deployPatcher) patch(req patchRequest) error {
	if !dp.isLeaderFunc() {
		log.Infof("Not leader, skipping")
		return nil
	}
	if req.TargetObjKind != "Deployment" {
		log.Errorf("Request filtering is broken, expected deployment requests got %q", req.TargetObjKind)
	}
	deploy, err := dp.k8sClient.AppsV1().Deployments(req.TargetObjNamespace).Get(context.TODO(), req.TargetObjName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	langAnnotationKey := fmt.Sprintf(libVersionAnnotationKeyFormat, req.Language)
	if deploy.Spec.Template.GetLabels()[admissionEnabledLabelKey] == "true" && deploy.Spec.Template.GetAnnotations()[langAnnotationKey] == req.LibVersion {
		log.Infof("Label and annotation are already applied and up-to-date on deployment %q", req.TargetObjName)
		return nil
	}
	configAnnotationKey := fmt.Sprintf(libConfigAnnotationKeyFormat, req.Language)
	if req.TraceSampleRate == "" {
		req.TraceSampleRate = "1"
	}
	libConf := common.LibConfig{TraceSampleRate: req.TraceSampleRate}
	configAnnotationVal, err := json.Marshal(libConf)
	if err != nil {
		return err
	}
	configAnnotationValEsc := strings.ReplaceAll(string(configAnnotationVal), `"`, `\"`)
	patch := []byte(fmt.Sprintf(`{"spec": {"template":{"metadata":{"annotations":{"%s":"%s","%s":"%s"},"labels":{"%s":"true"}}}}}`, langAnnotationKey, req.LibVersion, configAnnotationKey, configAnnotationValEsc, admissionEnabledLabelKey))
	log.Infof("Patching %s/%s with %s", req.TargetObjNamespace, req.TargetObjName, string(patch))
	_, err = dp.k8sClient.AppsV1().Deployments(req.TargetObjNamespace).Patch(context.TODO(), req.TargetObjName, types.StrategicMergePatchType, patch, v1.PatchOptions{})
	return err
}
