// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build trivy

package trivy

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	local2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/containerd/containerd"
	"github.com/docker/docker/client"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

const (
	cleanupTimeout      = 30 * time.Second
	OSAnalyzers         = "os"
	LanguagesAnalyzers  = "languages"
	SecretAnalyzers     = "secret"
	ConfigFileAnalyzers = "config"
	LicenseAnalyzers    = "license"
)

// ContainerdAccessor is a function that should return a containerd client
type ContainerdAccessor func() (cutil.ContainerdItf, error)

// CollectorConfig allows to pass configuration
type CollectorConfig struct {
	CacheProvider     CacheProvider
	ClearCacheOnClose bool
}

// Collector uses trivy to generate a SBOM
type Collector struct {
	config       CollectorConfig
	cache        cache.Cache
	cacheCleaner CacheCleaner
	detector     local.OspkgDetector
	dbConfig     db.Config
	vulnClient   vulnerability.Client
	marshaler    *cyclonedx.Marshaler
}

var globalCollector *Collector

func getDefaultArtifactOption(root string, opts sbom.ScanOptions) artifact.Option {
	option := artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: DefaultDisabledCollectors(opts.Analyzers),
		Slow:              !opts.Fast,
		SBOMSources:       []string{},
		DisabledHandlers:  DefaultDisabledHandlers(),
	}

	if len(opts.Analyzers) == 1 && opts.Analyzers[0] == OSAnalyzers {
		option.OnlyDirs = []string{"etc", "var/lib/dpkg", "var/lib/rpm", "lib/apk"}
		if root != "" {
			// OnlyDirs is handled differently for image than for filesystem.
			// This needs to be fixed properly but in the meantime, use absolute
			// paths for fs and relative paths for images.
			for i := range option.OnlyDirs {
				option.OnlyDirs[i] = filepath.Join(root, option.OnlyDirs[i])
			}
		}
	}

	return option
}

// defaultCollectorConfig returns a default collector configuration
// However, accessors still need to be filled in externally
func defaultCollectorConfig(cacheLocation string) CollectorConfig {
	collectorConfig := CollectorConfig{
		ClearCacheOnClose: true,
	}

	collectorConfig.CacheProvider = cacheProvider(cacheLocation, config.Datadog.GetBool("sbom.cache.enabled"))

	return collectorConfig
}

func cacheProvider(cacheLocation string, useCustomCache bool) func() (cache.Cache, CacheCleaner, error) {
	if useCustomCache {
		return func() (cache.Cache, CacheCleaner, error) {
			return NewCustomBoltCache(
				cacheLocation,
				config.Datadog.GetInt("sbom.cache.max_cache_entries"),
				config.Datadog.GetInt("sbom.cache.max_disk_size"),
			)
		}
	}

	return func() (cache.Cache, CacheCleaner, error) {
		return NewBoltCache(cacheLocation)
	}
}

func DefaultDisabledCollectors(enabledAnalyzers []string) []analyzer.Type {
	sort.Strings(enabledAnalyzers)
	analyzersDisabled := func(analyzers string) bool {
		index := sort.SearchStrings(enabledAnalyzers, analyzers)
		return index >= len(enabledAnalyzers) || enabledAnalyzers[index] != analyzers
	}

	var disabledAnalyzers []analyzer.Type
	if analyzersDisabled(OSAnalyzers) {
		disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeOSes...)
	}
	if analyzersDisabled(LanguagesAnalyzers) {
		disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeLanguages...)
	}
	if analyzersDisabled(SecretAnalyzers) {
		disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
	}
	if analyzersDisabled(ConfigFileAnalyzers) {
		disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeConfigFiles...)
	}
	if analyzersDisabled(LicenseAnalyzers) {
		disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeLicenseFile)
	}

	return disabledAnalyzers
}

func DefaultDisabledHandlers() []ftypes.HandlerType {
	return []ftypes.HandlerType{ftypes.UnpackagedPostHandler}
}

func NewCollector(cfg config.Config) (*Collector, error) {
	config := defaultCollectorConfig(cfg.GetString("sbom.cache_directory"))
	config.ClearCacheOnClose = cfg.GetBool("sbom.clear_cache_on_exit")

	dbConfig := db.Config{}
	fanalCache, cacheCleaner, err := config.CacheProvider()
	if err != nil {
		return nil, err
	}

	return &Collector{
		config:       config,
		cache:        fanalCache,
		cacheCleaner: cacheCleaner,
		detector:     ospkg.Detector{},
		dbConfig:     dbConfig,
		vulnClient:   vulnerability.NewClient(dbConfig),
		marshaler:    cyclonedx.NewMarshaler(""),
	}, nil
}

func GetGlobalCollector(cfg config.Config) (*Collector, error) {
	if globalCollector != nil {
		return globalCollector, nil
	}

	collector, err := NewCollector(cfg)
	if err != nil {
		return nil, err
	}

	globalCollector = collector
	return globalCollector, nil
}

func (c *Collector) Close() error {
	if c.config.ClearCacheOnClose {
		if err := c.cache.Clear(); err != nil {
			return fmt.Errorf("error when clearing trivy cache: %w", err)
		}
	}

	return c.cache.Close()
}

func (c *Collector) GetCacheCleaner() CacheCleaner {
	return c.cacheCleaner
}

func (c *Collector) ScanDockerImage(ctx context.Context, imgMeta *workloadmeta.ContainerImageMetadata, client client.ImageAPIClient, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	fanalImage, cleanup, err := convertDockerImage(ctx, client, imgMeta)
	if cleanup != nil {
		defer cleanup()
	}

	if err != nil {
		return nil, fmt.Errorf("unable to convert docker image, err: %w", err)
	}

	return c.scanImage(ctx, fanalImage, imgMeta, scanOptions)
}

func (c *Collector) ScanContainerdImage(ctx context.Context, imgMeta *workloadmeta.ContainerImageMetadata, img containerd.Image, client cutil.ContainerdItf, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	fanalImage, cleanup, err := convertContainerdImage(ctx, client.RawClient(), imgMeta, img)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to convert containerd image, err: %w", err)
	}

	return c.scanImage(ctx, fanalImage, imgMeta, scanOptions)
}

func (c *Collector) ScanContainerdImageFromFilesystem(ctx context.Context, imgMeta *workloadmeta.ContainerImageMetadata, img containerd.Image, client cutil.ContainerdItf, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	imagePath, err := os.MkdirTemp(os.TempDir(), fmt.Sprintf("containerd-image-*"))
	if err != nil {
		return nil, fmt.Errorf("unable to create temp dir, err: %w", err)
	}
	defer func() {
		err := os.RemoveAll(imagePath)
		if err != nil {
			log.Errorf("Unable to remove temp dir: %s, err: %v", imagePath, err)
		}
	}()

	// Computing duration of containerd lease
	deadline, _ := ctx.Deadline()
	expiration := deadline.Sub(time.Now().Add(cleanupTimeout))

	cleanUp, err := client.MountImage(ctx, expiration, imgMeta.Namespace, img, imagePath)
	if err != nil {
		return nil, fmt.Errorf("unable to mount containerd image, err: %w", err)
	}

	defer func() {
		cleanUpContext, cleanUpContextCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := cleanUp(cleanUpContext)
		cleanUpContextCancel()
		if err != nil {
			log.Errorf("Unable to clean up mounted image, err: %v", err)
		}
	}()

	return c.scanFilesystem(ctx, imagePath, imgMeta, scanOptions)
}

func (c *Collector) scanFilesystem(ctx context.Context, path string, imgMeta *workloadmeta.ContainerImageMetadata, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	cache := c.cache
	if scanOptions.NoCache {
		cache = &memoryCache{}
	}

	fsArtifact, err := local2.NewArtifact(path, cache, getDefaultArtifactOption(path, scanOptions))
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from fs, err: %w", err)
	}

	bom, err := c.scan(ctx, fsArtifact, applier.NewApplier(cache), imgMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal report to sbom format, err: %w", err)
	}

	return bom, nil
}

func getLambdaCodeURL(cfg aws.Config, functionName string, region string) (url string, err error) {

	cfg.Region = region
	l := lambda.NewFromConfig(cfg)
	ctx := context.TODO()
	params := &lambda.GetFunctionInput{FunctionName: &functionName}
	output, err := l.GetFunction(ctx, params)
	if err != nil {
		return "", err
	}

	return *output.Code.Location, nil
}

func downloadFile(url string, filepath string) (err error) {

	// Create the destination file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func downloadLambdaCode(functionName string, region string, destination string) (err error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	url, err := getLambdaCodeURL(cfg, functionName, region)
	if err != nil {
		return err
	}

	err = downloadFile(url, destination)
	if err != nil {
		return err
	}

	return nil
}

func extractZip(zipPath string, destinationPath string) (err error) {
	// Open a zip archive for reading.
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	// Iterate through the files in the archive,
	// printing some of their contents.
	for _, f := range r.File {
		dest := filepath.Join(destinationPath, f.Name)
		if strings.HasSuffix(f.Name, "/") {
			err = os.MkdirAll(dest, 0700)
			if err != nil {
				log.Debugf("%v", err)
			}
		} else {
			reader, err := f.Open()
			if err != nil {
				log.Debugf("%v", err)
			}
			defer reader.Close()
			writer, err := os.Create(dest)
			_, err = io.Copy(writer, reader)
			if err != nil {
				log.Debugf("%v", err)
			}
		}
	}
	return nil
}

func (c *Collector) ScanLambda(ctx context.Context, functionName string, awsRegion string, scanOptions sbom.ScanOptions) (sbom.Report, error) {

	zipDir, err := os.MkdirTemp("", "zipPath")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(zipDir)
	archivePath := filepath.Join(zipDir, "code.zip")

	err = downloadLambdaCode(functionName, awsRegion, archivePath)
	if err != nil {
		return nil, err
	}

	extractedPath := filepath.Join(zipDir, "extract")
	err = os.Mkdir(extractedPath, 0700)
	if err != nil {
		return nil, err
	}

	err = extractZip(archivePath, extractedPath)
	if err != nil {
		return nil, err
	}

	return c.scanFilesystem(ctx, extractedPath, nil, scanOptions)
}

func (c *Collector) ScanFilesystem(ctx context.Context, path string, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	return c.scanFilesystem(ctx, path, nil, scanOptions)
}

func (c *Collector) scan(ctx context.Context, artifact artifact.Artifact, applier applier.Applier, imgMeta *workloadmeta.ContainerImageMetadata) (sbom.Report, error) {
	if imgMeta != nil {
		artifactReference, err := artifact.Inspect(ctx) // called by the scanner as well
		if err != nil {
			return nil, err
		}
		c.cacheCleaner.setKeysForEntity(imgMeta.EntityID.ID, append(artifactReference.BlobIDs, artifactReference.ID))
	}

	s := scanner.NewScanner(local.NewScanner(applier, c.detector, c.vulnClient), artifact)
	trivyReport, err := s.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{},
		SecurityChecks:      []string{},
		ScanRemovedPackages: false,
		ListAllPackages:     true,
	})
	if err != nil {
		return nil, err
	}

	return &TrivyReport{
		Report:    trivyReport,
		marshaler: c.marshaler,
	}, nil
}

func (c *Collector) scanImage(ctx context.Context, fanalImage ftypes.Image, imgMeta *workloadmeta.ContainerImageMetadata, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	imageArtifact, err := image2.NewArtifact(fanalImage, c.cache, getDefaultArtifactOption("", scanOptions))
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from image, err: %w", err)
	}

	bom, err := c.scan(ctx, imageArtifact, applier.NewApplier(c.cache), imgMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal report to sbom format, err: %w", err)
	}

	return bom, nil
}

func (c *Collector) ScanVM(ctx context.Context, target, region string, scanOptions sbom.ScanOptions) (sbom.Report, error) {
	opts := getDefaultArtifactOption("", scanOptions)
	opts.AWSRegion = region
	vmArtifact, err := vm.NewArtifact(target, c.cache, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from image, err: %w", err)
	}

	bom, err := c.scan(ctx, vmArtifact, applier.NewApplier(c.cache), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal report to sbom format, err: %w", err)
	}

	return bom, nil
}
