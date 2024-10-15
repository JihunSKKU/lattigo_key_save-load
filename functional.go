package lattigo_key

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

// Rotation rotates the input ciphertext op0 by k positions and stores the result in opOut.
func (ctx *Context) Rotation(op0 *rlwe.Ciphertext, k int, opOut *rlwe.Ciphertext) (err error) {
	eval := ctx.evalPool.Get().(*hefloat.Evaluator)
	defer ctx.evalPool.Put(eval)

	rots := optimizeRotation(k, ctx.params.MaxSlots())
	if err := eval.Rotate(op0, rots[0], opOut); err != nil {
		return err
	}
	for _, r := range rots[1:] {
		if err := eval.Rotate(opOut, r, opOut); err != nil {
			return err
		}
	}
	return nil
}

// RotationNew creates a new ciphertext that is the result of rotating op0 by k positions.
func (ctx *Context) RotationNew(op0 *rlwe.Ciphertext, k int) (opOut *rlwe.Ciphertext, err error) {
	eval := ctx.evalPool.Get().(*hefloat.Evaluator)
	opOut = hefloat.NewCiphertext(*eval.GetParameters(), op0.Degree(), op0.Level())
	ctx.evalPool.Put(eval)

	if err = ctx.Rotation(op0, k, opOut); err != nil {
		return nil, err
	}

	return opOut, nil
}