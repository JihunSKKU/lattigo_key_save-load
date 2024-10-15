package lattigo_key

import (
	"fmt"
	"os"
	"reflect"
	"sync"
	"unsafe"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
)

func (ctx *Context) SaveKeys(dirPath string) error {
	// 기존 폴더 삭제 및 재생성
	if _, err := os.Stat(dirPath); err == nil {
        err = os.RemoveAll(dirPath)
        if err != nil {
            return fmt.Errorf("failed to remove existing directory: %v", err)
        }
    }
	err := os.MkdirAll(dirPath, os.ModePerm)
    if err != nil {
        return fmt.Errorf("failed to create directory: %v", err)
    }
	err = os.MkdirAll(dirPath+"/galks", os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Parameters 저장
	paramFile, err := os.Create(dirPath + "/params")
    if err != nil {
        return err
    }
    defer paramFile.Close()
    paramBytes, err := ctx.params.MarshalBinary()
    if err != nil {
        return err
    }
    paramFile.Write(paramBytes)
	fmt.Println("Successfully saved parameters")

	btparamFile, err := os.Create(dirPath + "/btparams")
	if err != nil {
		return err
	}
	defer btparamFile.Close()
	btparamBytes, err := ctx.btparams.MarshalBinary()
	if err != nil {
		return err
	}
	btparamFile.Write(btparamBytes)
	fmt.Println("Successfully saved bootstrapping parameters")

	// SecretKey 저장
    skFile, err := os.Create(dirPath + "/sk.key")
    if err != nil {
        return err
    }
    defer skFile.Close()
    skBytes, err := ctx.sk.MarshalBinary()
    if err != nil {
        return err
    }
    skFile.Write(skBytes)
	fmt.Println("Successfully saved secret key")

    // PublicKey 저장
    pkFile, err := os.Create(dirPath + "/pk.key")
    if err != nil {
        return err
    }
    defer pkFile.Close()
    pkBytes, err := ctx.pk.MarshalBinary()
    if err != nil {
        return err
    }
    pkFile.Write(pkBytes)
	fmt.Println("Successfully saved public key")

    // RelinearizationKey 저장
    rlkFile, err := os.Create(dirPath + "/rlk.key")
    if err != nil {
        return err
    }
    defer rlkFile.Close()
    rlkBytes, err := ctx.rlk.MarshalBinary()
    if err != nil {
        return err
    }
    rlkFile.Write(rlkBytes)
	fmt.Println("Successfully saved relinearization key")

    // GaloisKeys 저장
    for i, galk := range ctx.galKs {
        galkFile, err := os.Create(fmt.Sprintf("%s/galks/galk_%d.key", dirPath, i))
        if err != nil {
            return err
        }
        defer galkFile.Close()
        galkBytes, err := galk.MarshalBinary()
        if err != nil {
            return err
        }
        galkFile.Write(galkBytes)
    }
	fmt.Println("Successfully saved galois keys")

    // Bootstrapping Evaluation Key 저장
    btpFile, err := os.Create(dirPath + "/btp.key")
    if err != nil {
        return err
    }
    defer btpFile.Close()
    btBytes, err := ctx.btpkeys.MarshalBinary()
    if err != nil {
        return err
    }
    btpFile.Write(btBytes)

	btpMemSetFile, err := os.Create(dirPath + "/btp_memset.key")
	if err != nil {
		return err
	}
	defer btpMemSetFile.Close()
	btpMemSetBytes, err := ctx.btpkeys.MemEvaluationKeySet.MarshalBinary()
	if err != nil {
		return err
	}
	btpMemSetFile.Write(btpMemSetBytes)
	fmt.Println("Successfully saved bootstrapping evaluation keys")

	// 암호문 생성 및 저장
    values := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
    ptxt := hefloat.NewPlaintext(ctx.params, ctx.params.MaxLevel())
    ctx.ecd.Encode(values, ptxt)
    ctxt, err := ctx.enc.EncryptNew(ptxt)
    if err != nil {
        return err
    }
    
    ctxtBytes, err := ctxt.MarshalBinary()
    if err != nil {
        return err
    }
    err = os.WriteFile(dirPath+"/test_ctxt", ctxtBytes, 0644)
    if err != nil {
        return err
    }

    return nil
}

func LoadKeys(dirPath string) (*Context, error) {
    ctx := &Context{}

    // Parameters 로드
    paramBytes, err := os.ReadFile(dirPath + "/params")
    if err != nil {
        return nil, err
    }
    ctx.params = hefloat.Parameters{}
    if err := ctx.params.UnmarshalBinary(paramBytes); err != nil {
        return nil, err
    }
	fmt.Println("Successfully loaded parameters")

	// Bootstrapping Parameters 로드
	btparamBytes, err := os.ReadFile(dirPath + "/btparams")
	if err != nil {
		return nil, err
	}
	ctx.btparams = bootstrapping.Parameters{}
	if err := ctx.btparams.UnmarshalBinary(btparamBytes); err != nil {
		return nil, err
	}
	fmt.Println("Successfully loaded bootstrapping parameters")

    // SecretKey 로드
    skBytes, err := os.ReadFile(dirPath + "/sk.key")
    if err != nil {
        return nil, err
    }
    ctx.sk = new(rlwe.SecretKey)
    if err := ctx.sk.UnmarshalBinary(skBytes); err != nil {
        return nil, err
    }
	fmt.Println("Successfully loaded secret key")

    // PublicKey 로드
    pkBytes, err := os.ReadFile(dirPath + "/pk.key")
    if err != nil {
        return nil, err
    }
    ctx.pk = new(rlwe.PublicKey)
    if err := ctx.pk.UnmarshalBinary(pkBytes); err != nil {
        return nil, err
    }
	fmt.Println("Successfully loaded public key")

    // RelinearizationKey 로드
    rlkBytes, err := os.ReadFile(dirPath + "/rlk.key")
    if err != nil {
        return nil, err
    }
    ctx.rlk = new(rlwe.RelinearizationKey)
    if err := ctx.rlk.UnmarshalBinary(rlkBytes); err != nil {
        return nil, err
    }
	fmt.Println("Successfully loaded relinearization key")

    // GaloisKeys 로드
    i := 0
    for {
        galkBytes, err := os.ReadFile(fmt.Sprintf("%s/galks/galk_%d.key", dirPath, i))
        if os.IsNotExist(err) {
            break
        }
        if err != nil {
            return nil, err
        }
        galk := new(rlwe.GaloisKey)
        if err := galk.UnmarshalBinary(galkBytes); err != nil {
            return nil, err
        }
        ctx.galKs = append(ctx.galKs, galk)
        i++
    }
	fmt.Println("Successfully loaded galois keys")

    // Bootstrapping Evaluation Key 로드
	btMemSetBytes, err := os.ReadFile(dirPath + "/btp_memset.key")
	if err != nil {
		return nil, err
	}
    ctx.btpkeys = new(bootstrapping.EvaluationKeys)
	ctx.btpkeys.MemEvaluationKeySet = new(rlwe.MemEvaluationKeySet)
	if err := ctx.btpkeys.MemEvaluationKeySet.UnmarshalBinary(btMemSetBytes); err != nil {
		return nil, err
	}

    btBytes, err := os.ReadFile(dirPath + "/btp.key")
    if err != nil {
        return nil, err
    }
	ctx.btpkeys.MemEvaluationKeySet = rlwe.NewMemEvaluationKeySet(ctx.rlk, ctx.galKs...)
	if err := ctx.btpkeys.UnmarshalBinary(btBytes); err != nil {
        return nil, err
    }
	fmt.Println("Successfully loaded bootstrapping evaluation keys")


    // 암호문 로드 및 테스트
    ctxtBytes, err := os.ReadFile(dirPath + "/test_ctxt")
    if err != nil {
        return nil, err
    }
    ctxt := new(rlwe.Ciphertext)
    if err := ctxt.UnmarshalBinary(ctxtBytes); err != nil {
        return nil, err
    }
    
    ctx.enc = rlwe.NewEncryptor(ctx.params, ctx.pk)
    ctx.dec = rlwe.NewDecryptor(ctx.params, ctx.sk)
	ctx.ecd = hefloat.NewEncoder(ctx.params)
	ctx.eval = hefloat.NewEvaluator(ctx.params, ctx.btpkeys.MemEvaluationKeySet)
	ctx.evalPool = &sync.Pool{
		New: func() interface{} {
			if ctx.eval != nil {
				return ctx.eval.ShallowCopy()
			}
			return nil
		},
	}

	ctx.fillPool()

    // 암호문 복호화 테스트
    ptxt := ctx.dec.DecryptNew(ctxt)
    values := make([]float64, ctxt.Slots())
    if err := ctx.ecd.Decode(ptxt, values); err != nil {
        return nil, err
    }
    fmt.Println("Decrypted values:", values[:6])

	
	// Bootstrapping test (Error)
	ctx.btpEval, err = bootstrapping.NewEvaluator(ctx.btparams, ctx.btpkeys)
	if err != nil {
		return nil, err
	}

	// fmt.Println("Bootstrapping test")
	// btCtxt, err := ctx.btpEval.Bootstrap(ctxt)
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println("Successfully bootstrapped")

	// btPtxt := ctx.dec.DecryptNew(btCtxt)
	// btValues := make([]float64, btCtxt.Slots())
	// if err := ctx.ecd.Decode(btPtxt, btValues); err != nil {
	// 	return nil, err
	// }
	// fmt.Println("Bootstrapped values:", btValues[:6])

    return ctx, nil
}


func (ctx *Context) PrintKeySizes() {
	fmt.Printf("params size: %d Bytes\n", unsafe.Sizeof(ctx.params))

	fmt.Printf("sk size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.sk)))/1048576)
	fmt.Printf("pk size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.pk)))/1048576)
	fmt.Printf("rlk size: %.2f MB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.rlk)))/1048576)
	fmt.Printf("galks size: %.2f GB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.galKs)))/1073741824)
	fmt.Printf("btpkeys size: %.2f GB\n", float64(calculateDeepSize(reflect.ValueOf(ctx.btpkeys)))/1073741824)
}