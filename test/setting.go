package test

import (
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

func initLogQ(depth, logScale int) (logQ []int) {
	logQ = make([]int, depth+1)
	logQ[0] = logScale + 10
	for i := 1; i <= depth; i++ {
		logQ[i] = logScale
	}
	return
}

func initParams() (params hefloat.Parameters) {
	const (
		logSlots 	= 13
		depth 		= 7
		logScale 	= 50		
	)

	params, err := hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN: 				logSlots+1,
			LogQ: 				initLogQ(depth, logScale),
			LogP: 				[]int{61, 61},
			LogDefaultScale: 	logScale,
			RingType: 			ring.Standard,
		})
	if err != nil {
		panic(err)
	}
	return
}

func initBtParams() (params hefloat.Parameters, btparams bootstrapping.Parameters) {
	params, _ = hefloat.NewParametersFromLiteral(bootstrapping.N16QP1546H192H32.SchemeParams)

	btpParamsLit := bootstrapping.ParametersLiteral{
		LogN: 	utils.Pointy(16),
		LogP: 	[]int{61, 61, 61, 61},
		Xs:		params.Xs(),
	}

	btparams, _ = bootstrapping.NewParametersFromLiteral(params, btpParamsLit)

	return
}