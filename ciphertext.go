package lattigo_key

import (
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

type Ciphertext struct {
	data 	[]*rlwe.Ciphertext
	size 	 int
	interval int
	constVal float64
	space	 int
}

func (c *Ciphertext) GetData() []*rlwe.Ciphertext {
	return c.data
}

func (c *Ciphertext) GetConst() float64 {
	return c.constVal
}

func (c *Ciphertext) CopyNew() *Ciphertext {
	newData := make([]*rlwe.Ciphertext, len(c.data))
	
	wg := sync.WaitGroup{}
	wg.Add(len(c.data))
	for i, ct := range c.data {
		go func(i int, ct *rlwe.Ciphertext) {
			defer wg.Done()
			if ct != nil {
				newData[i] = ct.CopyNew()
			}
		}(i, ct)
	}
	wg.Wait()

	return &Ciphertext{
		data: 		newData,
		size: 		c.size,
		interval: 	c.interval,
		constVal: 	c.constVal,
		space: 	  	c.space,
	}
}