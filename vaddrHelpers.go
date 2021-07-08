package sevStep

const (
	pageShift = 12
)

func OnSamePage(vaddr1, vaddr2 uint64) bool {
	return (vaddr1 >> pageShift) == (vaddr2 >> pageShift)
}
