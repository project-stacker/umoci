package mutate

import (
	"io"
	"io/ioutil"
	"runtime"

	"github.com/apex/log"
	zstd "github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/opencontainers/umoci/pkg/system"
	"github.com/pkg/errors"
)

// Compressor is an interface which users can use to implement different
// compression types.
type Compressor interface {
	// Compress sets up the streaming compressor for this compression type.
	Compress(io.Reader) (io.ReadCloser, error)

	// MediaTypeSuffix returns the suffix to be added to the layer to
	// indicate what compression type is used, e.g. "gzip", or "" for no
	// compression.
	MediaTypeSuffix() string

	// WithOpt applies an option and can be chained.
	WithOpt(CompressorOpt) Compressor

	// BytesRead returns the number of bytes read from the uncompressed input
	// stream at the current time, no guarantee of completion.
	BytesRead() int64
}

// CompressorOpt is a compressor option which can be used to configure a
// compressor.
type CompressorOpt interface{}

type noopCompressor struct{}

func (nc noopCompressor) Compress(r io.Reader) (io.ReadCloser, error) {
	return ioutil.NopCloser(r), nil
}

func (nc noopCompressor) MediaTypeSuffix() string {
	return ""
}

func (nc noopCompressor) BytesRead() int64 {
	return -1
}

// NoopCompressor provides no compression.
var NoopCompressor Compressor = &noopCompressor{}

func (nc noopCompressor) WithOpt(CompressorOpt) Compressor {
	return nc
}

// GzipCompressor provides gzip compression.
var GzipCompressor Compressor = &gzipCompressor{blockSize: 256 << 10}

type GzipBlockSize int

type gzipCompressor struct {
	blockSize int
	bytesRead int64
}

func (gz *gzipCompressor) Compress(reader io.Reader) (io.ReadCloser, error) {
	pipeReader, pipeWriter := io.Pipe()

	gzw := gzip.NewWriter(pipeWriter)
	if err := gzw.SetConcurrency(gz.blockSize, 2*runtime.NumCPU()); err != nil {
		return nil, errors.Wrapf(err, "set concurrency level to %v blocks", 2*runtime.NumCPU())
	}
	go func() {
		bytesRead, err := system.Copy(gzw, reader)
		if err != nil {
			log.Warnf("gzip compress: could not compress layer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(errors.Wrap(err, "compressing layer"))
			return
		}
		gz.bytesRead = bytesRead
		if err := gzw.Close(); err != nil {
			log.Warnf("gzip compress: could not close gzip writer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(errors.Wrap(err, "close gzip writer"))
			return
		}
		if err := pipeWriter.Close(); err != nil {
			log.Warnf("gzip compress: could not close pipe: %v", err)
			// We don't CloseWithError because we cannot override the Close.
			return
		}
	}()

	return pipeReader, nil
}

func (gz gzipCompressor) MediaTypeSuffix() string {
	return "gzip"
}

func (gz gzipCompressor) WithOpt(opt CompressorOpt) Compressor {
	switch val := opt.(type) {
	case GzipBlockSize:
		gz.blockSize = int(val)
	}

	return &gz
}

func (gz gzipCompressor) BytesRead() int64 {
	return gz.bytesRead
}

// ZstdCompressor provides zstd compression.
var ZstdCompressor Compressor = &zstdCompressor{}

type zstdCompressor struct {
	bytesRead int64
}

func (zs *zstdCompressor) Compress(reader io.Reader) (io.ReadCloser, error) {

	pipeReader, pipeWriter := io.Pipe()
	zw, err := zstd.NewWriter(pipeWriter)
	if err != nil {
		return nil, err
	}
	go func() {
		bytesRead, err := system.Copy(zw, reader)
		if err != nil {
			log.Warnf("zstd compress: could not compress layer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(errors.Wrap(err, "compressing layer"))
			return
		}
		zs.bytesRead = bytesRead
		if err := zw.Close(); err != nil {
			log.Warnf("zstd compress: could not close gzip writer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(errors.Wrap(err, "close zstd writer"))
			return
		}
		if err := pipeWriter.Close(); err != nil {
			log.Warnf("zstd compress: could not close pipe: %v", err)
			// We don't CloseWithError because we cannot override the Close.
			return
		}
	}()

	return pipeReader, nil
}

func (zs zstdCompressor) MediaTypeSuffix() string {
	return "zstd"
}

func (zs zstdCompressor) WithOpt(CompressorOpt) Compressor {
	return &zs
}

func (zs zstdCompressor) BytesRead() int64 {
	return zs.bytesRead
}
