package lattigo_key

type Plaintext struct {
	data     [][]float64 	// The actual plaintext data
	size     int     		// The size of the data
	interval int  			// The interval of the data
	constVal float64      	// A constant value associated with the data
	space 	 int     		// The space size of the data
}

func (p *Plaintext) GetData() [][]float64 {
	return p.data
}

func NewPlaintext(data [][]float64) *Plaintext {
	return &Plaintext{
		data:     data,
		size:     len(data[0]),
		interval: 1,
		constVal: 1,
		space: 	  largestPowerOfTwoLessThan(len(data[0])),
	}
}