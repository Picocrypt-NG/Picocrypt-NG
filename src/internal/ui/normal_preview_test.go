package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"encoding/binary"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	fynetooltip "github.com/dweymouth/fyne-tooltip"
	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

func normalPreviewFixture() string {
	return filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes", "normal-standard-combined-ordered-one.pcv")
}

func TestNormalPreviewSelectionIsUnverifiedAndReadOnly(t *testing.T) {
	resetLocalizationForTest(t)
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
	fyne.DoAndWait(func() { a.onDrop([]string{normalPreviewFixture()}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		if a.commentsEntry.Text != "TEST ONLY comment" {
			t.Errorf("selected public comment = %q", a.commentsEntry.Text)
		}
		if !strings.Contains(a.commentsLabel.Text, "not verified") {
			t.Errorf("trust label = %q", a.commentsLabel.Text)
		}
		if a.commentsEntry.Disabled() {
			t.Error("preview text cannot be selected")
		}
		a.commentsEntry.SetText("attempted edit")
		if a.commentsEntry.Text != "TEST ONLY comment" {
			t.Error("read-only preview accepted edit")
		}
		snap := a.State.UISnapshot()
		if snap.PCV3Factor != app.PCV3FactorPolicyUnset || snap.KeyfileCount != 0 {
			t.Error("header selected factors")
		}
	})
}

// The one-keyfile variant is an unauthenticated public-header mutation, not a golden encryption.
func TestNormalMissingFactorsRenderCurrentExactCounts(t *testing.T) {
	for _, required := range []uint16{2, 1} {
		t.Run(fmt.Sprintf("header count %d", required), func(t *testing.T) {
			resetLocalizationForTest(t)
			dir := t.TempDir()
			input := normalPreviewFixture()
			if required == 1 {
				data, err := os.ReadFile(input)
				if err != nil {
					t.Fatal(err)
				}
				codecs, err := encoding.NewRSCodecs()
				if err != nil {
					t.Fatal(err)
				}
				// Both frozen capsules must claim the same tuple. Only their count field is changed.
				// Primary starts at 16; backup precedes the 48-byte trailer; count is decoded 100.
				for _, offset := range []int{16, len(data) - 960 - 48} {
					lane := data[offset+192 : offset+2*192]
					decoded, err := encoding.Decode(codecs.RS64, lane, false)
					if err != nil {
						t.Fatal(err)
					}
					binary.BigEndian.PutUint16(decoded[100-64:102-64], 1)
					encoded, err := encoding.Encode(codecs.RS64, decoded)
					if err != nil {
						t.Fatal(err)
					}
					copy(lane, encoded)
				}
				input = filepath.Join(t.TempDir(), "unauthenticated-one-keyfile-header.pcv")
				if err := os.WriteFile(input, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
			var deriving atomic.Bool
			a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
				reporter := request.Reporter
				request.Reporter = func(status pcv3operation.Status) error {
					if status.Code() == pcv3operation.StatusDerivingKey {
						deriving.Store(true)
					}
					if reporter != nil {
						return reporter(status)
					}
					return nil
				}
				return pcv3operation.Run(ctx, request)
			}
			fyne.DoAndWait(func() { a.onDrop([]string{input}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				ticket, _, ok := a.State.PCV3ReadyOutputSelection()
				if !ok || !a.State.SetPCV3OutputForReady(ticket, filepath.Join(dir, "plain")) {
					t.Fatal("set output")
				}
				a.State.Password = "mix"
				a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
				a.startPCV3Work()
			})
			a.workers.wait()
			fyne.DoAndWait(func() {
				result := a.pcv3Result
				if result == nil {
					t.Fatal("runner did not retain current result")
				}
				claims, supplied, ok := result.CredentialPolicyMismatch()
				if !ok || claims.KeyfileCount() != required || supplied != 0 {
					t.Fatalf("current result lost exact mismatch: count=%d supplied=%d available=%v outcome=%v stage=%v diagnostic=%v", claims.KeyfileCount(), supplied, ok, result.Outcome(), result.Stage(), result.Diagnostic())
				}
				text := pcv3RenderedText(a.pcv3Container)
				for _, want := range []string{"according to header (not verified)", fmt.Sprintf("Required keyfiles: %d", required), "Selected keyfiles: 0", "Password + keyfiles"} {
					if !strings.Contains(text, want) {
						t.Errorf("result lacks %q: %q", want, text)
					}
				}
				if deriving.Load() || result.Stage() != pcv3operation.StageCredentialPolicy || result.PublicationAttempted() || result.SourceDeletionAllowed() {
					t.Fatal("factor refusal derived keys or granted authority")
				}
				if a.State.Comments != "" || strings.Contains(text, "TEST ONLY comment") {
					t.Fatal("failed read promoted old preview")
				}
			})
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("factor refusal output = %v %v", entries, err)
			}
			if _, err := os.Stat(input); err != nil {
				t.Fatal("source was not retained")
			}
		})
	}
}

func TestNormalPreviewLanguageRefreshPreservesPayloadAndFactors(t *testing.T) {
	resetLocalizationForTest(t)
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
	fyne.DoAndWait(func() { a.onDrop([]string{normalPreviewFixture()}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		for _, code := range []LanguageCode{"en", "ru", "de", "fr", "es", "zh-Hans", "hi", "ko"} {
			if err := setActiveLanguage(code); err != nil {
				t.Fatal(err)
			}
			a.refreshLocalizedText()
			if a.commentsLabel.Text != tr("comments.unverified", "") || a.commentsLabel.ToolTip() != tr("comments.normal_tooltip", "") {
				t.Errorf("%s trust translation not refreshed", code)
			}
			requirements, ok := a.State.UISnapshot().PCV3NormalPreview.Factors()
			if !ok || a.commentsFactorHint.Text != pcv3HeaderFactorHint(requirements) || !a.commentsFactorHint.Visible() {
				t.Errorf("%s requirements not refreshed", code)
			}
			if a.commentsEntry.Text != "TEST ONLY comment" || a.State.UISnapshot().PCV3Factor != app.PCV3FactorPolicyUnset {
				t.Fatal("language changed payload or factors")
			}
		}
		if err := setActiveLanguage("en"); err != nil {
			t.Fatal(err)
		}
		a.refreshLocalizedText()
		captureNormalPreviewCanvas(t, a, "unverified")
		if !a.State.SelectPCV3D1() {
			t.Fatal("D1 selection")
		}
		a.updateUIState()
		if a.commentsEntry.Text != "" || a.commentsFactorHint.Visible() || strings.Contains(a.commentsLabel.ToolTip(), "stored openly") || a.commentsEntry.PlaceHolder != tr("comments.d1_placeholder", "") {
			t.Fatal("D1 retained Normal claims")
		}
		captureNormalPreviewCanvas(t, a, "d1")
	})
}

func captureNormalPreviewCanvas(t *testing.T, a *App, name string) {
	t.Helper()
	dir := os.Getenv("PICOCRYPT_UI_TEST_ARTIFACT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, "normal-preview-"+name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	a.Window.Content().Refresh()
	if err := png.Encode(file, a.Window.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

func TestNormalPreviewSplitUsesOnlyChunkZeroAndRemainsOptional(t *testing.T) {
	for _, front := range []int{1112, 1000, 975} {
		t.Run(strconv.Itoa(front), func(t *testing.T) {
			resetLocalizationForTest(t)
			data, err := os.ReadFile(normalPreviewFixture())
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(t.TempDir(), "split.pcv")
			for path, part := range map[string][]byte{base + ".0": data[:front], base + ".1": data[front:]} {
				if err := os.WriteFile(path, part, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
			fyne.DoAndWait(func() { a.onDrop([]string{base + ".1"}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				snap := a.State.UISnapshot()
				if snap.PCV3Route != app.PCV3RouteReady || !snap.Recombine {
					t.Fatal("optional preview broke split routing")
				}
				want := ""
				if front == 1112 {
					want = "TEST ONLY comment"
				}
				if a.commentsEntry.Text != want {
					t.Fatalf("chunk0=%d comment=%q want=%q", front, a.commentsEntry.Text, want)
				}
			})
		})
	}
}

func TestNormalPreviewSupersededDropCannotRestoreClaims(t *testing.T) {
	resetLocalizationForTest(t)
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
	result := routeDroppedFile(context.Background(), normalPreviewFixture(), false)
	if result.err != nil {
		t.Fatal(result.err)
	}
	fyne.DoAndWait(func() {
		old := a.folderScanGeneration
		a.folderScanGeneration++
		a.resetUI()
		a.applyDroppedFileRoute(context.Background(), old, normalPreviewFixture(), false, result)
		if a.State.Comments != "" || a.State.UISnapshot().PCV3Format != app.PCV3FormatNone {
			t.Fatal("superseded route resurrected preview")
		}
	})
	if _, err := result.source.Stat(); err == nil {
		t.Fatal("superseded route leaked source")
	}
}

func captureNormalPreviewHover(t *testing.T, a *App, confirmed bool) {
	t.Helper()
	if os.Getenv("PICOCRYPT_UI_TEST_ARTIFACT_DIR") == "" {
		return
	}
	var label *ttwidget.Label
	var content fyne.CanvasObject
	fyne.DoAndWait(func() {
		content = a.Window.Content()
		a.Window.SetContent(fynetooltip.AddWindowToolTipLayer(content, a.Window.Canvas()))
		label = a.commentsLabel
		if confirmed {
			label = a.commentsResultLabel
		}
		if label == nil {
			t.Fatal("missing tooltip label")
		}
		pos := a.fyneApp.Driver().AbsolutePositionForObject(label).Add(fyne.NewPos(10, 10))
		label.MouseIn(&desktop.MouseEvent{PointEvent: fyne.PointEvent{AbsolutePosition: pos, Position: fyne.NewPos(10, 10)}})
	})
	time.Sleep(850 * time.Millisecond)
	fyne.DoAndWait(func() {
		name := "unverified-tooltip"
		if confirmed {
			name = "confirmed-tooltip"
		}
		captureNormalPreviewCanvas(t, a, name)
		label.MouseOut()
		fynetooltip.DestroyWindowToolTipLayer(a.Window.Canvas())
		a.Window.SetContent(content)
	})
}

func TestNormalPreviewHoverUsesActualLabel(t *testing.T) {
	if os.Getenv("PICOCRYPT_UI_TEST_ARTIFACT_DIR") == "" {
		t.Skip("optional software tooltip capture destination not set")
	}
	resetLocalizationForTest(t)
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
	fyne.DoAndWait(func() { a.onDrop([]string{normalPreviewFixture()}) })
	waitForDropProcessing(t, a)
	captureNormalPreviewHover(t, a, false)
}

func verifyAuthenticatedCommentLanguageRefresh(t *testing.T, a *App) {
	t.Helper()
	fyne.DoAndWait(func() {
		for _, code := range []LanguageCode{"en", "ru", "de", "fr", "es", "zh-Hans", "hi", "ko"} {
			if err := setActiveLanguage(code); err != nil {
				t.Fatal(err)
			}
			a.refreshLocalizedText()
			if a.commentsResultLabel == nil || a.commentsResultLabel.Text != tr("comments.authenticated", "") || a.commentsResultLabel.ToolTip() != tr("comments.normal_tooltip", "") {
				t.Errorf("%s confirmed heading/tooltip not refreshed", code)
			}
			snap := a.State.UISnapshot()
			if snap.Comments != "TEST ONLY comment" || snap.CommentsPreviewState != app.CommentsPreviewAuthenticated {
				t.Fatal("language refresh changed authenticated payload/trust")
			}
		}
		if err := setActiveLanguage("en"); err != nil {
			t.Fatal(err)
		}
		a.refreshLocalizedText()
	})
}

// Hover must not outlive the form when Enter starts an operation without mouse movement.
func TestNormalPreviewEnterRetiresPendingAndVisibleHover(t *testing.T) {
	for _, visible := range []bool{false, true} {
		t.Run(strconv.FormatBool(visible), func(t *testing.T) {
			resetLocalizationForTest(t)
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(a.State.Reset) })
			fyne.DoAndWait(func() { a.onDrop([]string{normalPreviewFixture()}) })
			waitForDropProcessing(t, a)
			var layer *fyne.Container
			var original fyne.CanvasObject
			fyne.DoAndWait(func() {
				original = a.Window.Content()
				content := fynetooltip.AddWindowToolTipLayer(original, a.Window.Canvas()).(*fyne.Container)
				layer = content.Objects[1].(*fyne.Container)
				a.Window.SetContent(content)
			})
			t.Cleanup(func() {
				fyne.DoAndWait(func() {
					a.commentsLabel.MouseOut()
					fynetooltip.DestroyWindowToolTipLayer(a.Window.Canvas())
					a.Window.SetContent(original)
				})
			})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
				<-release
				_ = request.Source.Close()
				_ = request.Factors.Close()
				return pcv3operation.Run(context.Background(), &pcv3operation.Request{})
			}
			fyne.DoAndWait(func() {
				a.State.Password = "mix"
				a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
				a.updateUIState()
				pos := a.fyneApp.Driver().AbsolutePositionForObject(a.commentsLabel).Add(fyne.NewPos(10, 10))
				a.commentsLabel.MouseIn(&desktop.MouseEvent{PointEvent: fyne.PointEvent{AbsolutePosition: pos, Position: fyne.NewPos(10, 10)}})
			})
			if visible {
				time.Sleep(850 * time.Millisecond)
				fyne.DoAndWait(func() {
					if len(layer.Objects) == 0 {
						t.Fatal("hover never became visible")
					}
				})
			}
			fyne.DoAndWait(func() {
				a.onDesktopKeyDown(&fyne.KeyEvent{Name: fyne.KeyReturn})
				if !a.State.IsWorking() || a.configurationForm.Visible() {
					t.Fatal("Enter did not replace ready form with operation surface")
				}
			})
			time.Sleep(850 * time.Millisecond)
			fyne.DoAndWait(func() {
				if len(layer.Objects) != 0 {
					t.Error("hidden ready comment hover survived Enter-start")
				}
			})
			releaseOnce.Do(func() { close(release) })
			a.workers.wait()
			fyne.DoAndWait(func() {})
		})
	}
}

func TestNormalCommentResultShutdownSeparatesVisualRetirement(t *testing.T) {
	for _, uiOwned := range []bool{false, true} {
		t.Run(strconv.FormatBool(uiOwned), func(t *testing.T) {
			resetLocalizationForTest(t)
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			var label *ttwidget.Label
			var retired atomic.Int32
			source, err := os.Open(normalPreviewFixture())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = source.Close() })
			fyne.DoAndWait(func() {
				if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, source.Name(), "plain", 0) {
					t.Fatal("set held source")
				}
				label = ttwidget.NewLabel("retained result label")
				label.SetToolTip("result help")
				label.OnMouseOut = func() { retired.Add(1) }
				a.commentsResultLabel = label
				a.pcv3Result = pcv3operation.Run(context.Background(), &pcv3operation.Request{})
			})
			if uiOwned {
				fyne.DoAndWait(a.beginOrderlyShutdown)
			} else {
				a.stopSourcesAndContexts()
				a.stopSourcesAndContexts()
			}
			want := int32(0)
			if uiOwned {
				want = 1
			}
			if got := retired.Load(); got != want {
				t.Fatalf("MouseOut calls=%d want=%d for UI-owned=%v", got, want, uiOwned)
			}
			if a.pcv3Result != nil {
				t.Fatal("shutdown retained result owner")
			}
			if _, err := source.Stat(); err == nil {
				t.Fatal("shutdown retained held source descriptor")
			}
			if uiOwned {
				a.workers.wait()
				var done <-chan struct{}
				fyne.DoAndWait(func() { done = a.workersDone })
				if done != nil {
					<-done
				}
				fyne.DoAndWait(a.shutdownSentinelTick)
			}
		})
	}
}

func TestResultCommentTooltipRequiresCurrentSingleReadContext(t *testing.T) {
	resetLocalizationForTest(t)
	for _, format := range []app.PCV3Format{app.PCV3FormatNormal, app.PCV3FormatD1} {
		snap := app.UISnapshot{Mode: "decrypt", PCV3Format: format, PCV3Route: app.PCV3RouteTransferred}
		if resultCommentsToolTip(snap) == "" {
			t.Fatal("current single read lost proven format explanation")
		}
		snap.Recursively = true
		if resultCommentsToolTip(snap) != "" {
			t.Fatal("batch tooltip inferred format from final per-file selection")
		}
		snap.Recursively = false
		snap.PCV3Route = app.PCV3RouteReady
		if resultCommentsToolTip(snap) != "" {
			t.Fatal("retained result tooltip inferred format from unrelated ready selection")
		}
	}
}

// Archive follow-up removes the result subtree while its worker still owns the effect.
func TestNormalCommentArchiveFollowUpRetiresHoverWithoutClosingReview(t *testing.T) {
	for _, visible := range []bool{false, true} {
		for _, cancellable := range []bool{false, true} {
			t.Run("visible="+strconv.FormatBool(visible)+"/cancellable="+strconv.FormatBool(cancellable), func(t *testing.T) {
				resetLocalizationForTest(t)
				a := createUIReadyDropTestApp(t, newTestFyneApp(t))
				var result *pcv3operation.Result
				var generation uint64
				var label *ttwidget.Label
				var layer *fyne.Container
				var original fyne.CanvasObject
				var retired atomic.Int32
				fyne.DoAndWait(func() {
					result, generation = preparePCV3ArchiveFollowUpState(t, a)
					a.updateUIState()
					// This lifecycle label tests hover ownership, not reader authentication.
					label = ttwidget.NewLabel("retained comment heading")
					label.SetToolTip("retained comment help")
					label.OnMouseOut = func() { retired.Add(1) }
					a.commentsResultLabel = label
					a.pcv3Container.Add(label)
					original = a.Window.Content()
					content := fynetooltip.AddWindowToolTipLayer(original, a.Window.Canvas()).(*fyne.Container)
					layer = content.Objects[1].(*fyne.Container)
					a.Window.SetContent(content)
					pos := a.fyneApp.Driver().AbsolutePositionForObject(label).Add(fyne.NewPos(10, 10))
					label.MouseIn(&desktop.MouseEvent{PointEvent: fyne.PointEvent{AbsolutePosition: pos, Position: fyne.NewPos(10, 10)}})
				})
				t.Cleanup(func() {
					fyne.DoAndWait(func() {
						label.MouseOut()
						if a.pcv3ArchiveReviewModal != nil {
							a.pcv3ArchiveReviewModal.Hide()
							a.pcv3ArchiveReviewModal = nil
						}
						fynetooltip.DestroyWindowToolTipLayer(a.Window.Canvas())
						a.Window.SetContent(original)
						a.releasePCV3Result()
						a.State.Reset()
					})
				})
				release := make(chan struct{})
				entered := make(chan struct{})
				var releaseOnce sync.Once
				releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
				ensurePCV3TestWorkersReleased(t, a, releaseWorker)
				if visible {
					time.Sleep(850 * time.Millisecond)
					fyne.DoAndWait(func() {
						if len(layer.Objects) == 0 {
							t.Fatal("result hover never became visible")
						}
					})
				}
				startPCV3ArchiveFollowUpForTest(t, a, result, generation, cancellable, func(context.Context) *pcv3operation.Result {
					close(entered)
					<-release
					return pcv3operation.Run(context.Background(), &pcv3operation.Request{})
				})
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("follow-up worker did not start")
				}
				fyne.DoAndWait(func() {
					if !a.State.IsWorking() || a.pcv3Result != result || canvasTreeContainsObject(a.pcv3Container, label) {
						t.Fatal("follow-up did not replace result subtree while retaining effect owner")
					}
					if retired.Load() != 1 {
						t.Error("removed result label did not retire its pending/visible hover")
					}
				})
				time.Sleep(850 * time.Millisecond)
				fyne.DoAndWait(func() {
					if len(layer.Objects) != 0 {
						t.Error("result comment tooltip survived archive-follow-up progress")
					}
					review := dialog.NewInformation("Archive review", "Review remains open", a.Window)
					a.pcv3ArchiveReviewModal = review
					review.Show()
					overlay := a.Window.Canvas().Overlays().Top()
					if overlay == nil {
						t.Fatal("review modal never became visible")
					}
					a.updateUIState()
					if a.pcv3ArchiveReviewModal != review || a.Window.Canvas().Overlays().Top() != overlay {
						t.Error("comment-hover retirement closed active archive-review modal")
					}
					review.Hide()
					a.pcv3ArchiveReviewModal = nil
				})
				releaseWorker()
				a.workers.wait()
				fyne.DoAndWait(func() {})
			})
		}
	}
}
