package auditscan

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner is the "still working" line the scan shows while it walks the
// transcripts. On a machine with a year of sessions the scan takes long enough
// that silence reads as a hang.
//
// The animation is suppressed when stdout is not a terminal. The npm tool
// writes the carriage returns regardless, which puts a line of half-overwritten
// frames into any redirected output; the completion line still prints, so
// nothing a script reads has gone missing.
type Spinner struct {
	mu      sync.Mutex
	message string
	stop    chan struct{}
	done    chan struct{}
}

func NewSpinner(message string) *Spinner {
	return &Spinner{message: message}
}

func (s *Spinner) Start() *Spinner {
	if !colorEnabled {
		return s
	}
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		frame := 0
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.mu.Lock()
				msg := s.message
				s.mu.Unlock()
				icon := paint(spinnerFrames[frame%len(spinnerFrames)], ansiCyan)
				fmt.Fprintf(os.Stdout, "\r  %s %s", icon, dim(msg))
				frame++
			}
		}
	}()
	return s
}

func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// Stop clears the animated line before printing anything else, so the final
// message does not land on top of a half-drawn frame.
func (s *Spinner) Stop(finalMessage string) {
	if s.stop != nil {
		close(s.stop)
		<-s.done
		s.stop = nil
		fmt.Fprint(os.Stdout, "\r\x1b[2K")
	}
	if finalMessage != "" {
		fmt.Printf("  %s %s\n", paint("✔", ansiGreen), dim(finalMessage))
	}
}
