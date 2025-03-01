package storage_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/storage"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
)

func TestItStoresFilesInFilesystem(t *testing.T) {
	dir := t.TempDir()
	storage, err := storage.New(config.Storage{
		Type: "filesystem",
		Config: map[string]any{
			"dir": dir,
		},
	})
	require.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	name := test.Word()
	contents := test.Sentence(15)

	require.Nil(t, storage.Upload(ctx, name, strings.NewReader(contents)))

	file, err := os.ReadFile(fmt.Sprintf("%s/%s", dir, name))
	require.Nil(t, err)
	require.Equal(t, contents, string(file))
}

func TestItStoresFilesInS3(t *testing.T) {
	b := test.Boiler(t)

	storage, err := boiler.Resolve[objstore.Bucket](b)
	require.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	name := test.Word()
	contents := test.Sentence(15)

	require.Nil(t, storage.Upload(ctx, name, strings.NewReader(contents)))

	file, err := storage.Get(ctx, name)
	require.Nil(t, err)
	body, err := io.ReadAll(file)
	require.Nil(t, err)
	require.Equal(t, contents, string(body))
}
