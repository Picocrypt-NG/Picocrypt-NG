package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

func commentsPreviewReadable(state app.CommentsPreviewState) bool {
	return state == app.CommentsPreviewNormal || state == app.CommentsPreviewUnverified || state == app.CommentsPreviewAuthenticated
}

func commentsToolTip(snap app.UISnapshot) string {
	if snap.Mode != "decrypt" {
		return ""
	}
	if snap.PCV3Format == app.PCV3FormatNormal {
		return tr("comments.normal_tooltip", "In Normal PCV3 the comment is stored openly. Confirmed means its integrity was verified after successful decryption and full container verification.")
	}
	if snap.PCV3Format == app.PCV3FormatD1 {
		return tr("comments.d1_tooltip", "In PCV3 D1 the comment is encrypted. It is shown only after successful decryption and full container verification.")
	}
	return ""
}

// A retained batch result may not describe the final per-file selection.
func resultCommentsToolTip(snap app.UISnapshot) string {
	if snap.Recursively || snap.PCV3Route != app.PCV3RouteTransferred {
		return ""
	}
	return commentsToolTip(snap)
}

func setCommentLabelTooltip(label *ttwidget.Label, text string) {
	if label.ToolTip() != text {
		label.MouseOut()
		label.SetToolTip(text)
	}
}

func pcv3FactorRequirementText(requirements pcv3operation.FactorRequirements) string {
	switch requirements.Policy() {
	case pcv3operation.FactorPolicyPasswordOnly:
		return tr("pcv3.factor.password", "Password only")
	case pcv3operation.FactorPolicyKeyfilesOnly:
		return tr("pcv3.factor.keyfiles", "Keyfiles only")
	case pcv3operation.FactorPolicyPasswordAndKeyfiles:
		return tr("pcv3.factor.combined", "Password + keyfiles")
	}
	return ""
}

func pcv3HeaderFactorHint(requirements pcv3operation.FactorRequirements) string {
	return tr("pcv3.factor.header_hint", "According to header (not verified): {{.Policy}}. Required keyfiles: {{.Required}}.", map[string]any{"Policy": pcv3FactorRequirementText(requirements), "Required": requirements.KeyfileCount()})
}

func pcv3ExactFactorMismatchCopy(requirements pcv3operation.FactorRequirements, supplied uint16) string {
	return tr("pcv3.factor.exact_mismatch", "Requirements according to header (not verified): {{.Policy}}. Required keyfiles: {{.Required}}. Selected keyfiles: {{.Selected}}. Check factor mode and keyfile order. No key derivation or output started.", map[string]any{"Policy": pcv3FactorRequirementText(requirements), "Required": requirements.KeyfileCount(), "Selected": supplied})
}
