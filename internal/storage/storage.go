package storage

import (
	"errors"

	"github.com/go-kit/log"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
	"github.com/thanos-io/objstore/providers/s3"
	"gopkg.in/yaml.v3"
)

var (
	ErrUnsupportedStorageType = errors.New("storage type is not supported")
	ErrInvalidRootDir         = errors.New("invalid filesystem root directory")
)

func New(conf config.Storage) (objstore.Bucket, error) {
	switch conf.Type {
	case "s3":
		return newS3(conf)
	case "filesystem":
		return newFilesystem(conf)
	default:
		return nil, ErrUnsupportedStorageType
	}
}

func newS3(conf config.Storage) (objstore.Bucket, error) {
	by, err := yaml.Marshal(conf.Config)
	if err != nil {
		return nil, err
	}
	return s3.NewBucket(log.NewNopLogger(), by, "storage")
}

func newFilesystem(conf config.Storage) (objstore.Bucket, error) {
	dir, ok := conf.Config["dir"]
	if !ok {
		return nil, ErrInvalidRootDir
	}
	rootDir, ok := dir.(string)
	if !ok {
		return nil, ErrInvalidRootDir
	}
	return filesystem.NewBucket(rootDir)
}
