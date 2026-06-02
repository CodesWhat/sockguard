package logging

// close stops the background refill goroutine and waits for it to exit. In
// production the requestIDGenerator deliberately runs for the lifetime of the
// process, so close() exists solely for test cleanup — keeping it in a _test.go
// file keeps it out of the production binary.
func (g *requestIDGenerator) close() {
	if g == nil {
		return
	}
	close(g.stopCh)
	g.wg.Wait()
}
