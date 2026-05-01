package sasl

import (
	"strconv"
	"testing"
)

func BenchmarkZero(b *testing.B) {
	sliceSizes := []int{16, 64, 256, 1024, 4096}
	for _, size := range sliceSizes {
		b.Run("size_"+strconv.Itoa(size), func(b *testing.B) {
			slice := make([]byte, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zero(slice)
			}
		})
	}
}
