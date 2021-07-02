package zip

import (
	gozip "archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type Mutator struct {
	mutators []internalMutator
}

func NewMutator() *Mutator {
	return &Mutator{}
}

type actionType int

const (
	actionPassthrough actionType = iota
	actionMutate
)

func (m *Mutator) AddEntryContentMutator(entryName string, fn EntryContentMutatorFunc) {
	m.mutators = append(m.mutators, internalMutator{
		action: func(entry *gozip.File) actionType {
			if entry.Name == entryName {
				return actionMutate
			}
			return actionPassthrough
		},
		contentMutate: func(inbytes []byte) ([]byte, error) {
			reader := bytes.NewBuffer(inbytes)
			var writer bytes.Buffer
			err := fn(&writer, reader)
			if err != nil {
				return nil, err
			}
			return writer.Bytes(), nil
		},
	})
}

type internalMutator struct {
	action        func(entry *gozip.File) actionType
	contentMutate func(inbytes []byte) ([]byte, error)
}
type EntryContentMutatorFunc func(writer io.Writer, reader io.Reader) error

func (m *Mutator) Run(ctx context.Context, w io.WriteCloser, r io.ReaderAt, inSize int64) error {

	outerLog := ctxzap.Extract(ctx)

	zipReader, err := gozip.NewReader(r, inSize)
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}

	// open target archive
	zipWriter := gozip.NewWriter(w)

	for _, sourceEntry := range zipReader.File {
		log := outerLog.With(zap.String("filename", sourceEntry.Name))
		srcReader, err := sourceEntry.Open()
		if err != nil {
			log.Error("Failed to open zip entry.", zap.Error(err))
			return fmt.Errorf("failed to open zip: %w", err)
		}

		// read src entry
		srcEntryBytes, err := io.ReadAll(srcReader)
		if err != nil {
			log.Error("Failed to read zip entry.", zap.String("entry", sourceEntry.Name), zap.Error(err))
			return fmt.Errorf("failed to read zip entry: %w", err)
		}

		for _, intMut := range m.mutators {
			if intMut.action(sourceEntry) == actionMutate {
				mutatedBytes, err := intMut.contentMutate(srcEntryBytes)
				if err != nil {
					log.Error("Failed to mutate zip entry.", zap.Error(err))
					return fmt.Errorf("failed to mutate zip entry: %w", err)
				}
				srcEntryBytes = mutatedBytes
			}
		}

		targetEntry, err := zipWriter.Create(sourceEntry.Name)
		if err != nil {
			log.Error("Failed to open target zip.",
				zap.String("entry", sourceEntry.Name), zap.Error(err))
			return fmt.Errorf("failed to open zip: %w", err)
		}

		n, err := targetEntry.Write(srcEntryBytes)
		if err != nil {
			log.Error("Failed to write zip entry.", zap.Error(err))
			return fmt.Errorf("failed to write zip entry: %w", err)
		}
		if n != len(srcEntryBytes) {
			log.Error("Short write to zip entry.", zap.Any("written", n), zap.Any("expected", len(srcEntryBytes)))
			return fmt.Errorf("short write to zip entry: %d/%d", n, len(srcEntryBytes))
		}

		//log.Info("Handled zip entry.", zap.String("entry", sourceEntry.Name))
	}
	zipWriter.Close()
	w.Close()

	return nil
}
