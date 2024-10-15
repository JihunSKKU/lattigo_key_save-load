package lattigo_key

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"unsafe"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
)

type Context struct {
	params 		hefloat.Parameters
	ecd 		*hefloat.Encoder
	kgen 		*rlwe.KeyGenerator
	sk 			*rlwe.SecretKey
	pk 			*rlwe.PublicKey
	rlk 		*rlwe.RelinearizationKey
	galKs        []*rlwe.GaloisKey
	enc 		*rlwe.Encryptor
	dec 		*rlwe.Decryptor
	eval 		*hefloat.Evaluator
	evalPool 	*sync.Pool
	btpkeys 	*bootstrapping.EvaluationKeys
}

func (ctx *Context) GetEval() (eval *hefloat.Evaluator) {
	eval = ctx.evalPool.Get().(*hefloat.Evaluator)
	return
}
func (ctx *Context) PutEval(eval *hefloat.Evaluator) (){
	ctx.evalPool.Put(eval)
	return
}

func NewContext(params hefloat.Parameters, btparams bootstrapping.Parameters) (ctx *Context) {
// func NewContext(params hefloat.Parameters) (ctx *Context) {
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	ctx = &Context{
		params: params,
		ecd: 	hefloat.NewEncoder(params),
		kgen: 	kgen,
		sk: 	sk,
		pk: 	pk,
		enc: 	rlwe.NewEncryptor(params, pk),
		dec: 	rlwe.NewDecryptor(params, sk),
	}

	if params.PCount() != 0 {
		ctx.rlk = kgen.GenRelinearizationKeyNew(sk)
		slots := params.MaxSlots()
		rots := genRots(slots)
		var galEls []uint64
		for i := 0; i < len(rots); i++ {
			galEls = append(galEls, params.GaloisElement(rots[i]))
		}

		ctx.galKs = kgen.GenGaloisKeysNew(galEls, sk)

		ctx.eval = hefloat.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(
				ctx.rlk, ctx.galKs...))

		ctx.evalPool = &sync.Pool{
			New: func() interface{} {
				if ctx.eval != nil {
					return ctx.eval.ShallowCopy()
				}
				return nil
			},
		}

		ctx.fillPool()
	}

	ctx.btpkeys, _, _ = btparams.GenEvaluationKeys(ctx.sk)

	return ctx
}

func (ctx *Context) fillPool() {
	numEval := 16

	wg := sync.WaitGroup{}
	list := make([]*hefloat.Evaluator, numEval)
	
	wg.Add(numEval)
	for i := 0; i < numEval; i++ {
		go func(i int) {
			defer wg.Done()
			list[i] = ctx.evalPool.Get().(*hefloat.Evaluator)
		}(i)
	}
	wg.Wait()

	wg.Add(numEval)
	for i := 0; i < numEval; i++ {
		go func(i int) {
			defer wg.Done()
			ctx.evalPool.Put(list[i])
		}(i)
	}
	wg.Wait()

	return
}

func (ctx *Context) Encrypt(ptxt *Plaintext) (ctxt *Ciphertext) {
	var err error

	// Currently, it panics when the number of features in data is larger than slots
	slots := ctx.params.MaxSlots()
	if slots < ptxt.space {
		panic("heccfd: Plaintext space is too large for the current context")
	}

	maxLevel := ctx.params.MaxLevel()
	numImgs := len(ptxt.data)

	ctxt = &Ciphertext{
		data: 		make([]*rlwe.Ciphertext, numImgs),
		size: 		ptxt.size,
		interval: 	ptxt.interval,
		constVal: 	ptxt.constVal,
		space: 		ptxt.space,
	}

	for i := 0; i < numImgs; i++ {
		encoded := hefloat.NewPlaintext(ctx.params, maxLevel)
		if err = ctx.ecd.Encode(ptxt.data[i], encoded); err != nil {
			panic(err)
		}
		if ctxt.data[i], err = ctx.enc.EncryptNew(encoded); err != nil {
			panic(err)
		}
	}
		
	return
}

func (ctx *Context) Decrypt(ctxt *Ciphertext) (ptxt *Plaintext) {
	var err error

	numCtxt := len(ctxt.data)

	ptxt = &Plaintext{
		data: 		make([][]float64, numCtxt),
		size: 		ctxt.size,
		interval: 	ctxt.interval,
		constVal: 	ctxt.constVal,
		space: 		ctxt.space,
	}

	ptxtC := make([][]complex128, numCtxt)
	for i := 0; i < numCtxt; i++ {
		decrypted := ctx.dec.DecryptNew(ctxt.data[i])
		ptxtC[i] = make([]complex128, ctxt.data[i].Slots())
		if err = ctx.ecd.Decode(decrypted, ptxtC[i]); err != nil {
			panic(err)
		}
	}

	for i := 0; i < numCtxt; i++ {
		ptxt.data[i] = make([]float64, ctxt.data[i].Slots())
		for p := 0; p < ctxt.data[i].Slots(); p++ {
			ptxt.data[i][p] = real(ptxtC[i][p])
		}
	}

	return
}

type SerializableContext struct {
	Params hefloat.Parameters
	Sk     []byte
	Pk     []byte
	Rlk    []byte
	Galks  [][]byte
	// Btpkeys []byte
}

func (ctx *Context) SaveContext(filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)

	skBytes, err := ctx.sk.MarshalBinary()
	if err != nil {
		return err
	}
	encoder.Encode(skBytes)

	pkBytes, err := ctx.pk.MarshalBinary()
	if err != nil {
		return err
	}
	encoder.Encode(pkBytes)

	rlkBytes, err := ctx.rlk.MarshalBinary()
	if err != nil {
		return err
	}
	encoder.Encode(rlkBytes)

	for _, galk := range ctx.galKs {
		galkBytes, err := galk.MarshalBinary()
		if err != nil {
			return err
		}
		encoder.Encode(galkBytes)
	}

	btBytes, err := ctx.btpkeys.MarshalBinary()
	if err != nil {
		return err
	}
	encoder.Encode(btBytes)

	// sc := &SerializableContext{
	// 	Params: ctx.params,
	// 	Sk:     skBytes,
	// 	Pk:     pkBytes,
	// 	Rlk:    rlkBytes,
	// 	Galks:  Galks,
	// 	// Btpkeys: btBytes,
	// }

	// Test values
	values := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	ptxt := hefloat.NewPlaintext(ctx.params, ctx.params.MaxLevel())
	ctx.ecd.Encode(values, ptxt)
	ctxt, _ := ctx.enc.EncryptNew(ptxt)
	// Save the ctxt
	ctxtBytes, err := ctxt.MarshalBinary()
	if err != nil {
		return err
	}
	err = os.WriteFile("../context/ctxt", ctxtBytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LoadContext(filepath string) (*Context, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	sc := &SerializableContext{}
	err = json.Unmarshal(data, sc)
	if err != nil {
		return nil, err
	}

	ctx := &Context{
		params: sc.Params,
		ecd:    hefloat.NewEncoder(sc.Params),
		kgen:   rlwe.NewKeyGenerator(sc.Params),
	}

	ctx.sk = new(rlwe.SecretKey)
	if err = ctx.sk.UnmarshalBinary(sc.Sk); err != nil {
		return nil, err
	}

	ctx.pk = new(rlwe.PublicKey)
	if err = ctx.pk.UnmarshalBinary(sc.Pk); err != nil {
		return nil, err
	}

	ctx.rlk = new(rlwe.RelinearizationKey)
	if err = ctx.rlk.UnmarshalBinary(sc.Rlk); err != nil {
		return nil, err
	}

	// ctx.btpkeys = new(bootstrapping.EvaluationKeys)
	// if err = ctx.btpkeys.UnmarshalBinary(sc.Btpkeys); err != nil {
	// 	return nil, err
	// }

	ctx.enc = rlwe.NewEncryptor(sc.Params, ctx.pk)
	ctx.dec = rlwe.NewDecryptor(sc.Params, ctx.sk)

	if sc.Params.PCount() != 0 {
		slots := sc.Params.MaxSlots()
		rots := genRots(slots)
		var galEls []uint64
		for i := 0; i < len(rots); i++ {
			galEls = append(galEls, sc.Params.GaloisElement(rots[i]))
		}

		ctx.eval = hefloat.NewEvaluator(sc.Params, rlwe.NewMemEvaluationKeySet(
				ctx.rlk, ctx.kgen.GenGaloisKeysNew(galEls, ctx.sk)...))

		ctx.evalPool = &sync.Pool{
			New: func() interface{} {
				if ctx.eval != nil {
					return ctx.eval.ShallowCopy()
				}
				return nil
			},
		}

		ctx.fillPool()
	}

	// // Load the ctxt
	// ctxtBytes, err := os.ReadFile("../context/ctxt")
	// if err != nil {
	// 	return nil, err
	// }
	// ctxt := new(rlwe.Ciphertext)
	// if err = ctxt.UnmarshalBinary(ctxtBytes); err != nil {
	// 	return nil, err
	// }
	// fmt.Printf("ctxt (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctxt)))/1048576)

	// // Test context elements
	// ptxt := ctx.dec.DecryptNew(ctxt)
	// values := make([]float64, ctxt.Slots())
	// if err = ctx.ecd.Decode(ptxt, values); err != nil {
	// 	return nil, err
	// }
	// fmt.Println(values[:6])

	// newValues := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	// ctx.eval.MulRelin(ctxt, newValues, ctxt)
	// ptxt = ctx.dec.DecryptNew(ctxt)
	// values = make([]float64, ctxt.Slots())
	// if err = ctx.ecd.Decode(ptxt, values); err != nil {
	// 	return nil, err
	// }
	// fmt.Println(values[:6])

	return ctx, nil
}

func (ctx *Context) PrintKeySizes() {
	totalSize := reflect.TypeOf(*ctx).Size()
	fmt.Printf("Context struct size: %d Bytes\n", totalSize)

	// 각 필드의 메모리 사용량 분석
	fmt.Printf("params size: %d Bytes\n", unsafe.Sizeof(ctx.params))

	// 각 포인터가 가리키는 데이터의 실제 메모리 사용량
	fmt.Printf("ecd (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.ecd)))/1048576)
	fmt.Printf("kgen (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.kgen)))/1048576)
	fmt.Printf("sk (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.sk)))/1048576)
	fmt.Printf("pk (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.pk)))/1048576)
	fmt.Printf("rlk (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.rlk)))/1048576)
	fmt.Printf("enc (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.enc)))/1048576)
	fmt.Printf("dec (dereferenced) size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.dec)))/1048576)
	fmt.Printf("galk (dereferenced) size: %.2f GB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.eval))-calculateDeepSize(reflect.ValueOf(ctx.rlk)))/1073741824)
}

func calculateDeepSize(v reflect.Value) uintptr {
	if !v.IsValid() {
		return 0
	}

	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		if v.Kind() == reflect.Interface {
			return calculateDeepSize(v.Elem())
		}
		ptr := v.Pointer()
		return unsafe.Sizeof(ptr) + calculateDeepSize(v.Elem())

	case reflect.Array, reflect.Slice:
		size := v.Type().Size()
		for i := 0; i < v.Len(); i++ {
			size += calculateDeepSize(v.Index(i))
		}
		return size

	case reflect.Struct:
		size := v.Type().Size()
		for i := 0; i < v.NumField(); i++ {
			size += calculateDeepSize(v.Field(i))
		}
		return size

	case reflect.Map:
		size := v.Type().Size()
		for _, key := range v.MapKeys() {
			size += calculateDeepSize(key)
			size += calculateDeepSize(v.MapIndex(key))
		}
		return size

	default:
		return v.Type().Size()
	}
}