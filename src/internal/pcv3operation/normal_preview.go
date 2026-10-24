package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"context"
	"io"
)

// FactorRequirements and NormalPreview expose only unauthenticated public
// header hints. Neither value carries credential or output authority.
type (
	FactorRequirements = pcv3.FactorRequirements
	NormalPreview      = pcv3.NormalPreview
)

// PreviewNormal borrows the selected source without changing its position.
// The optional front-only preview never authenticates data or derives keys.
func PreviewNormal(ctx context.Context, source io.ReaderAt, sourceSize int64) (NormalPreview, error) {
	return pcv3.PreviewNormal(ctx, source, sourceSize)
}
