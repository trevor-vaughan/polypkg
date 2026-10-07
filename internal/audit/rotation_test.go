package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// seqEvent is a fixed-size event: a constant timestamp and a single-digit seq
// make every marshalled line the same length, so byte thresholds in these
// tests are exact multiples of one line.
func seqEvent(seq int) Event {
	return Event{
		Ts:    time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Scope: "user", TxID: "tx", Event: "test.event",
		Fields: map[string]any{"seq": seq},
	}
}

// lineLen is the on-disk length of one seqEvent line, newline included.
func lineLen() int64 {
	GinkgoHelper()
	data, err := json.Marshal(seqEvent(1))
	Expect(err).NotTo(HaveOccurred())
	return int64(len(data) + 1)
}

// seqs returns the seq field of every line in path, in file order.
func seqs(path string) []int {
	GinkgoHelper()
	data, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	out := []int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var line struct {
			Seq int `json:"seq"`
		}
		Expect(json.Unmarshal(sc.Bytes(), &line)).To(Succeed(), "line %q is not one whole JSON event", sc.Text())
		out = append(out, line.Seq)
	}
	return out
}

var _ = Describe("FileWriter rotation", func() {
	var logPath string

	BeforeEach(func() {
		logPath = filepath.Join(GinkgoT().TempDir(), "audit.log")
	})

	open := func(rot Rotation) *FileWriter {
		GinkgoHelper()
		w, err := NewRotatingFileWriter(logPath, rot)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = w.Close() })
		return w
	}

	It("rotates to .1 once the next event would cross the threshold", func() {
		w := open(Rotation{MaxBytes: 3 * lineLen(), Keep: 2})
		for i := 1; i <= 4; i++ {
			Expect(w.Write(seqEvent(i))).To(Succeed())
		}
		Expect(seqs(logPath+".1")).To(Equal([]int{1, 2, 3}), "exactly at the threshold is not over it")
		Expect(seqs(logPath)).To(Equal([]int{4}))
	})

	It("keeps at most Keep rotated files, dropping the oldest", func() {
		w := open(Rotation{MaxBytes: lineLen(), Keep: 2})
		for i := 1; i <= 5; i++ {
			Expect(w.Write(seqEvent(i))).To(Succeed())
		}
		Expect(seqs(logPath)).To(Equal([]int{5}))
		Expect(seqs(logPath + ".1")).To(Equal([]int{4}))
		Expect(seqs(logPath + ".2")).To(Equal([]int{3}))
		Expect(logPath + ".3").NotTo(BeAnExistingFile())
	})

	It("writes an event larger than the threshold whole into a file of its own", func() {
		w := open(Rotation{MaxBytes: 10, Keep: 1})
		Expect(w.Write(seqEvent(1))).To(Succeed())
		Expect(w.Write(seqEvent(2))).To(Succeed())
		Expect(seqs(logPath + ".1")).To(Equal([]int{1}))
		Expect(seqs(logPath)).To(Equal([]int{2}))
	})

	It("follows a rotation another writer made instead of appending to the rotated file", func() {
		rot := Rotation{MaxBytes: lineLen(), Keep: 3}
		w1 := open(rot)
		w2 := open(rot)
		Expect(w1.Write(seqEvent(1))).To(Succeed())
		Expect(w2.Write(seqEvent(2))).To(Succeed()) // rotates: .1 = [1]
		Expect(w1.Write(seqEvent(3))).To(Succeed()) // w1's handle is now .1; must follow, then rotate
		Expect(seqs(logPath)).To(Equal([]int{3}))
		Expect(seqs(logPath + ".1")).To(Equal([]int{2}))
		Expect(seqs(logPath + ".2")).To(Equal([]int{1}))
	})

	It("never interleaves or loses events from concurrent writers", func() {
		const writers, perWriter = 4, 25
		rot := Rotation{MaxBytes: 4 * lineLen(), Keep: writers * perWriter}
		var wg sync.WaitGroup
		for range writers {
			w := open(rot)
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := range perWriter {
					Expect(w.Write(seqEvent(i % 10))).To(Succeed())
				}
			}()
		}
		wg.Wait()
		total := len(seqs(logPath))
		for i := 1; ; i++ {
			p := fmt.Sprintf("%s.%d", logPath, i)
			if _, err := os.Stat(p); err != nil {
				break
			}
			total += len(seqs(p))
		}
		Expect(total).To(Equal(writers * perWriter))
	})

	It("still records the event when it cannot follow another writer's rotation", func() {
		rot := Rotation{MaxBytes: lineLen(), Keep: 3}
		w1 := open(rot)
		w2 := open(rot)
		Expect(w1.Write(seqEvent(1))).To(Succeed())
		Expect(w2.Write(seqEvent(2))).To(Succeed()) // rotates: .1 = [1], live = [2]
		// A directory squatting on the live name makes w1's reopen fail.
		Expect(os.Remove(logPath)).To(Succeed())
		Expect(os.Mkdir(logPath, 0o700)).To(Succeed())
		Expect(w1.Write(seqEvent(3))).To(Succeed(), "losing an audit record is worse than appending to the old file")
		Expect(seqs(logPath + ".1")).To(Equal([]int{1, 3}))
	})

	It("still records the event when rotation fails", func() {
		// A non-empty directory squatting on audit.log.1 makes rename(2) fail.
		Expect(os.MkdirAll(filepath.Join(logPath+".1", "occupied"), 0o700)).To(Succeed())
		w := open(Rotation{MaxBytes: lineLen(), Keep: 1})
		Expect(w.Write(seqEvent(1))).To(Succeed())
		Expect(w.Write(seqEvent(2))).To(Succeed())
		Expect(seqs(logPath)).To(Equal([]int{1, 2}))
		Expect(logPath + ".1").To(BeADirectory())
	})

	It("creates the log and its lock sidecar owner-only", func() {
		w := open(DefaultRotation)
		Expect(w.Write(seqEvent(1))).To(Succeed())
		for _, p := range []string{logPath, logPath + ".lock"} {
			info, err := os.Stat(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)), p)
		}
	})

	It("rejects a write after Close", func() {
		w, err := NewRotatingFileWriter(logPath, DefaultRotation)
		Expect(err).NotTo(HaveOccurred())
		Expect(w.Close()).To(Succeed())
		Expect(w.Write(seqEvent(1))).To(MatchError(ContainSubstring("closed")))
		Expect(w.Close()).To(Succeed(), "Close is idempotent")
	})

	DescribeTable("rejects a rotation that cannot bound the log",
		func(rot Rotation) {
			_, err := NewRotatingFileWriter(logPath, rot)
			Expect(err).To(MatchError(ContainSubstring("invalid audit log rotation")))
		},
		Entry("zero max bytes", Rotation{MaxBytes: 0, Keep: 3}),
		Entry("negative max bytes", Rotation{MaxBytes: -1, Keep: 3}),
		Entry("zero keep", Rotation{MaxBytes: 1 << 20, Keep: 0}),
	)

	It("defaults to 10 MiB and three rotated files", func() {
		Expect(DefaultRotation).To(Equal(Rotation{MaxBytes: 10 << 20, Keep: 3}))
	})
})
