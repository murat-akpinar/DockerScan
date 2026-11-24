package main

import (
	"testing"
	"time"
)

func severity(critical, high, medium int) map[string]int {
	return map[string]int{"CRITICAL": critical, "HIGH": high, "MEDIUM": medium}
}

// Her notun sınırı iki taraftan sınanır; eşik kayarsa quality gate sessizce değişir.
func TestComputeGrade(t *testing.T) {
	cases := []struct {
		name                   string
		critical, high, medium int
		want                   string
	}{
		{"temiz", 0, 0, 0, "A"},
		{"A sınırı", 0, 2, 5, "A"},
		{"HIGH A'yı aşar", 0, 3, 0, "B"},
		{"MEDIUM A'yı aşar", 0, 0, 6, "B"},
		{"B sınırı", 0, 5, 10, "B"},
		{"HIGH B'yi aşar", 0, 6, 0, "C"},
		{"MEDIUM B'yi aşar", 0, 0, 11, "C"},
		{"tek kritik en iyi C", 1, 0, 0, "C"},
		{"C sınırı", 2, 8, 0, "C"},
		{"MEDIUM C'nin altına düşürmez", 0, 0, 5000, "C"},
		{"kritik C'yi aşar", 3, 0, 0, "D"},
		{"HIGH C'yi aşar", 0, 9, 0, "D"},
		{"D sınırı", 9, 99, 0, "D"},
		{"kritik D'yi aşar", 10, 0, 0, "F"},
		{"HIGH D'yi aşar", 0, 100, 0, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := computeGrade(severity(c.critical, c.high, c.medium)); got != c.want {
				t.Errorf("computeGrade(C=%d H=%d M=%d) = %s, want %s", c.critical, c.high, c.medium, got, c.want)
			}
		})
	}
}

// LOW ve UNKNOWN nota girmez.
func TestComputeGradeIgnoresLowAndUnknown(t *testing.T) {
	if got := computeGrade(map[string]int{"LOW": 500, "UNKNOWN": 500}); got != "A" {
		t.Errorf("got %s, want A", got)
	}
}

func TestComputeProjectGrade(t *testing.T) {
	img := func(grade string, critical int) ImageGrade {
		return ImageGrade{Grade: grade, SeverityCount: map[string]int{"CRITICAL": critical}}
	}
	cases := []struct {
		name   string
		images []ImageGrade
		want   string
	}{
		{"imajsız", nil, "A"},
		{"tek imaj B kalır", []ImageGrade{img("B", 0)}, "B"},
		{"tamamı B kalır", []ImageGrade{img("B", 0), img("B", 0)}, "B"},
		{"tek imaj D kalır", []ImageGrade{img("D", 0)}, "D"},
		{"çoğunluk iyi, C yumuşar", []ImageGrade{img("C", 0), img("A", 0), img("A", 0)}, "B"},
		{"çoğunluk iyi, D yumuşar", []ImageGrade{img("D", 0), img("A", 0), img("A", 0)}, "C"},
		{"çoğunluk iyi, F yumuşar", []ImageGrade{img("F", 0), img("A", 0), img("A", 0)}, "D"},
		{"yarı yarıya yumuşamaz", []ImageGrade{img("D", 0), img("A", 0)}, "D"},
		{"kritikli C yumuşamaz", []ImageGrade{img("C", 2), img("A", 0), img("A", 0)}, "C"},
		{"kritikli D yumuşamaz", []ImageGrade{img("D", 6), img("A", 0), img("A", 0)}, "D"},
		{"kritik en kötü imajda olmasa da yumuşamaz", []ImageGrade{img("D", 0), img("C", 1), img("A", 0), img("A", 0), img("A", 0)}, "D"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := computeProjectGrade(c.images); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

// Eski bir yüksek-sürüm etiketi (test-v2.0), yeni gelen test-v1.0 taramasını
// maskelememeli: "son tarama" tarihe göre seçilir.
func TestLatestScanByDateIgnoresTagOrder(t *testing.T) {
	old := time.Date(2026, 11, 2, 11, 18, 13, 0, time.UTC)
	fresh := time.Date(2026, 11, 2, 14, 51, 20, 0, time.UTC)

	scans := []ScanSummary{
		{Tag: "test-v2.0", ModifiedAt: old, TotalVulns: 68},
		{Tag: "test-v1.0", ModifiedAt: fresh, TotalVulns: 0},
	}
	sortScansByDate(scans)

	latest, ok := latestScanByDate(scans)
	if !ok {
		t.Fatal("tarama bulunamadı")
	}
	if latest.Tag != "test-v1.0" || latest.TotalVulns != 0 {
		t.Fatalf("son tarama yanlış: tag=%s vulns=%d", latest.Tag, latest.TotalVulns)
	}
	if got := oldestScanDate(scans); !got.Equal(old) {
		t.Fatalf("ilk tarama tarihi yanlış: %v", got)
	}
}

func TestScansForTag(t *testing.T) {
	scans := []ScanSummary{
		{Tag: "test-v2.0", TotalVulns: 68},
		{Tag: "test-v1.0", TotalVulns: 0},
		{Tag: "test-v1.0", TotalVulns: 3},
	}

	if got := len(scansForTag(scans, "test-v1.0")); got != 2 {
		t.Fatalf("test-v1.0 için 2 tarama beklenirdi, %d geldi", got)
	}
	if got := len(scansForTag(scans, "")); got != 3 {
		t.Fatalf("etiket boşken tümü dönmeliydi, %d geldi", got)
	}
	if got := len(scansForTag(scans, "yok")); got != 0 {
		t.Fatalf("eşleşmeyen etikette boş dönmeliydi, %d geldi", got)
	}
}

// Sıralama TARİHE göre olmalı, etikete göre değil. Aynı imajın prod ve test
// taramaları bir arada durduğunda, etiket karşılaştırması ("prod" < "test") en
// yeni taramayı listenin SONUNA atıyordu. Scans[0]'ı "en yeni" kabul eden üç yer
// (/api/sbom envanteri, /api/summary CVE listesi ve deploy bilgisi) bu yüzden
// eski taramayı okuyordu.
func TestSortScansByDatePutsNewestFirstAcrossTags(t *testing.T) {
	eski := time.Date(2026, 10, 26, 14, 36, 45, 0, time.UTC)
	orta := time.Date(2026, 11, 2, 11, 33, 17, 0, time.UTC)
	yeni := time.Date(2026, 11, 2, 11, 33, 19, 0, time.UTC)

	scans := []ScanSummary{
		{Tag: "test-v1.0", ModifiedAt: eski, Filename: "a.json"},
		{Tag: "test-v1.0", ModifiedAt: orta, Filename: "b.json"},
		{Tag: "prod-v1.0", ModifiedAt: yeni, Filename: "c.json"},
	}
	sortScansByDate(scans)

	if !scans[0].ModifiedAt.Equal(yeni) || scans[0].Tag != "prod-v1.0" {
		t.Fatalf("en yeni tarama başta olmalı, bulunan: tag=%s tarih=%v", scans[0].Tag, scans[0].ModifiedAt)
	}
	if !scans[2].ModifiedAt.Equal(eski) {
		t.Fatalf("en eski tarama sonda olmalı, bulunan: %v", scans[2].ModifiedAt)
	}
	// Scans[0] = en yeni varsayımı artık tutuyor.
	if latest, ok := latestScanByDate(scans); !ok || latest.Filename != scans[0].Filename {
		t.Fatalf("latestScanByDate ile scans[0] uyuşmuyor")
	}
}

// Aynı saniyede yazılmış taramalarda sıra rastgele kalmamalı (sort.Slice kararlı değil).
func TestSortScansByDateIsDeterministicOnTies(t *testing.T) {
	an := time.Date(2026, 11, 2, 11, 33, 17, 0, time.UTC)
	scans := []ScanSummary{
		{ModifiedAt: an, Filename: "z.json"},
		{ModifiedAt: an, Filename: "a.json"},
	}
	sortScansByDate(scans)
	if scans[0].Filename != "a.json" {
		t.Fatalf("eşit tarihte dosya adına göre sıralanmalı, bulunan: %s", scans[0].Filename)
	}
}
