package filter

import "testing"

func restoreFilterIODeps(t *testing.T) {
	t.Helper()

	oldCreateTempFile := createTempFile
	oldRemoveFilePath := removeFilePath
	oldSeekToStart := seekToStart
	oldReadAllLimited := readAllLimited
	oldDrainReader := drainReader
	oldCloseReadCloser := closeReadCloser

	t.Cleanup(func() {
		createTempFile = oldCreateTempFile
		removeFilePath = oldRemoveFilePath
		seekToStart = oldSeekToStart
		readAllLimited = oldReadAllLimited
		drainReader = oldDrainReader
		closeReadCloser = oldCloseReadCloser
	})
}
