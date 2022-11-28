// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/DataDog/datadog-agent/pkg/security/api"
	cdx "github.com/DataDog/datadog-agent/pkg/security/api/cyclonedx"
)

// ToSBOMMessage returns an *api.SBOMMessage instance from an SBOM instance
func (s *SBOM) ToSBOMMessage() (*api.SBOMMessage, error) {
	msg := &api.SBOMMessage{
		Host:    s.Host,
		Service: s.Service,
		Source:  s.Source,
		Tags:    make([]string, len(s.Tags)),
		BOM:     cycloneDXToProto(s.Report.CycloneDX),
	}
	copy(msg.Tags, s.Tags)
	return msg, nil
}

func cycloneDXToProto(sbom *types.CycloneDX) *cdx.Bom {
	if sbom == nil {
		return nil
	}

	cycloneDXProto := &cdx.Bom{
		SpecVersion:  sbom.SpecVersion,
		Version:      int32(sbom.Version),
		SerialNumber: sbom.SerialNumber,
		Metadata:     cycloneDXMetadataToProto(sbom.Metadata),
		Components:   make([]*cdx.Component, len(sbom.Components)),
	}

	for _, elem := range sbom.Components {
		cycloneDXProto.Components = append(cycloneDXProto.Components, cycloneDXComponentToProto(elem))
	}
	return cycloneDXProto
}

func componentTypeToClassification(componentType types.ComponentType) cdx.Classification {
	switch componentType {
	case types.ComponentType(cyclonedx.ComponentTypeApplication):
		return cdx.Classification_CLASSIFICATION_APPLICATION
	case types.ComponentType(cyclonedx.ComponentTypeFramework):
		return cdx.Classification_CLASSIFICATION_FRAMEWORK
	case types.ComponentType(cyclonedx.ComponentTypeLibrary):
		return cdx.Classification_CLASSIFICATION_LIBRARY
	case types.ComponentType(cyclonedx.ComponentTypeOS):
		return cdx.Classification_CLASSIFICATION_OPERATING_SYSTEM
	case types.ComponentType(cyclonedx.ComponentTypeDevice):
		return cdx.Classification_CLASSIFICATION_DEVICE
	case types.ComponentType(cyclonedx.ComponentTypeFile):
		return cdx.Classification_CLASSIFICATION_FILE
	case types.ComponentType(cyclonedx.ComponentTypeContainer):
		return cdx.Classification_CLASSIFICATION_CONTAINER
	case types.ComponentType(cyclonedx.ComponentTypeFirmware):
		return cdx.Classification_CLASSIFICATION_FIRMWARE
	default:
		return cdx.Classification_CLASSIFICATION_NULL
	}
}

func cycloneDXComponentToProto(elem types.Component) *cdx.Component {
	return &cdx.Component{
		BomRef:   elem.BOMRef,
		MimeType: elem.MIMEType,
		Type:     componentTypeToClassification(elem.Type),
		Name:     elem.Name,
		Version:  elem.Version,
		Purl:     elem.PackageURL,
	}
}

func cycloneDXMetadataToProto(metadata types.Metadata) *cdx.Metadata {
	return &cdx.Metadata{
		// TODO: add Timestamp
		// Timestamp: &timestamp.Timestamp{
		// 	Seconds: 0,
		// 	Nanos:   0,
		// },
		Component: cycloneDXComponentToProto(metadata.Component),
	}
}
