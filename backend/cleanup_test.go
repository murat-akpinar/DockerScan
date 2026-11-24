package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// cleanupProjectDir en yeni `keep` taramayı tutup gerisini silmeli; meta
// dosyası tarama sayılmamalı ve silinmemeli.
func TestCleanupProjectDirKeepsLatest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()
	// 8 dosya, modTime'ları eskiye doğru: scan-0 en yeni, scan-7 en eski.
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "scan-"+strconv.Itoa(i)+".json")
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(-time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	meta := filepath.Join(dir, "meta-app.json")
	if err := os.WriteFile(meta, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := base.Add(-48 * time.Hour)
	if err := os.Chtimes(meta, old, old); err != nil {
		t.Fatal(err)
	}

	deleted, kept := cleanupProjectDir(dir, 5)
	if kept != 5 || deleted != 3 {
		t.Fatalf("got deleted=%d kept=%d, want deleted=3 kept=5", deleted, kept)
	}
	for i := 0; i < 8; i++ {
		_, err := os.Stat(filepath.Join(dir, "scan-"+strconv.Itoa(i)+".json"))
		exists := err == nil
		if i < 5 && !exists {
			t.Errorf("scan-%d silinmemeliydi", i)
		}
		if i >= 5 && exists {
			t.Errorf("scan-%d silinmeliydi", i)
		}
	}
	if _, err := os.Stat(meta); err != nil {
		t.Error("meta dosyasi silinmemeliydi")
	}
}

// keep'ten az dosya varsa hiçbir şey silinmemeli.
func TestCleanupProjectDirUnderLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(dir, "scan-"+strconv.Itoa(i)+".json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, kept := cleanupProjectDir(dir, 5); deleted != 0 || kept != 3 {
		t.Fatalf("got deleted=%d kept=%d, want deleted=0 kept=3", deleted, kept)
	}
}

func TestProjectNameMatchesSeparators(t *testing.T) {
	// CI kendi değişkeniyle soruyor, index imaj adından türetiyor → ayıraç farkı
	// quality gate'i 404'e düşürüyordu.
	if !projectNameMatches("my-app", "my_app") {
		t.Error("alt çizgi ile tire aynı sayılmalı")
	}
	if !projectNameMatches("my_app", "my-app") {
		t.Error("karşılaştırma simetrik olmalı")
	}
	if !projectNameMatches("My-App", "my_app") {
		t.Error("büyük/küçük harf fark etmemeli")
	}
	// Ayıraç SİLİNMEMELİ: bu ikisi ayrı projeler olabilir.
	if projectNameMatches("my-app", "myapp") {
		t.Error("tire silinmemeli: my-app ile myapp ayrı projeler")
	}
	if projectNameMatches("shop", "blog") {
		t.Error("alakasız adlar eşleşmemeli")
	}
}
