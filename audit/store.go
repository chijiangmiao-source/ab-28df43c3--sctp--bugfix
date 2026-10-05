package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

// MaxPackets 是一次捕获至多允许的包数。
const MaxPackets = 32

// BufferedItem 是缓存分片的展示项。
type BufferedItem struct {
	TSN    uint32 `json:"tsn"`
	SSN    uint16 `json:"ssn"`
	B      bool   `json:"b"`
	E      bool   `json:"e"`
	Length int    `json:"length"`
}

// StateView 是审计状态的只读视图。
type StateView struct {
	Initialized bool           `json:"initialized"`
	SrcPort     uint16         `json:"srcPort,omitempty"`
	DstPort     uint16         `json:"dstPort,omitempty"`
	VerTag      uint32         `json:"verTag,omitempty"`
	Stream      uint16         `json:"stream,omitempty"`
	CumTSN      uint32         `json:"cumTSN"`
	MaxTSN      uint32         `json:"maxTSN"`
	ExpectedSSN uint16         `json:"expectedSSN"`
	Buffered    []BufferedItem `json:"buffered"`
	Skipped     []Range        `json:"skipped"`
}

// View 是一个审计标识下的完整只读视图: 逐包裁决、状态与已交付消息。
type View struct {
	AuditID     string    `json:"auditId"`
	PacketCount int       `json:"packetCount"`
	Verdicts    []Verdict `json:"verdicts"`
	State       StateView `json:"state"`
	Messages    []Message `json:"messages"`
}

// View 生成会话的只读视图, 输出对同一冻结状态是确定性的。
func (s *Session) View() *View {
	buffered := make([]BufferedItem, 0, len(s.Buffered))
	for _, f := range s.Buffered {
		buffered = append(buffered, BufferedItem{TSN: f.TSN, SSN: f.SSN, B: f.B, E: f.E, Length: len(f.Data)})
	}
	sort.Slice(buffered, func(i, j int) bool { return buffered[i].TSN < buffered[j].TSN })
	skipped := append([]Range(nil), s.Skipped...)
	if skipped == nil {
		skipped = []Range{}
	}
	msgs := s.Messages
	if msgs == nil {
		msgs = []Message{}
	}
	verdicts := s.Verdicts
	if verdicts == nil {
		verdicts = []Verdict{}
	}
	return &View{
		AuditID:     s.ID,
		PacketCount: len(s.Verdicts),
		Verdicts:    verdicts,
		State: StateView{
			Initialized: s.Initialized,
			SrcPort:     s.SrcPort,
			DstPort:     s.DstPort,
			VerTag:      s.VerTag,
			Stream:      s.Stream,
			CumTSN:      s.CumTSN,
			MaxTSN:      s.MaxTSN,
			ExpectedSSN: s.ExpectedSSN,
			Buffered:    buffered,
			Skipped:     skipped,
		},
		Messages: msgs,
	}
}

// Conflict 表示提交与已冻结裁决冲突(同一捕获位置的字节不同)。
type Conflict struct {
	Index               int    `json:"index"`
	FrozenSHA256        string `json:"frozenSha256"`
	FrozenFirstBytesHex string `json:"frozenFirstBytesHex"`
	GotSHA256           string `json:"gotSha256"`
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID 校验稳定审计标识(同时保证可安全用作文件名)。
func ValidID(id string) bool {
	return idRe.MatchString(id)
}

// Store 按审计标识持久化冻结会话, 保证同一标识的重复读取结果一致。
type Store struct {
	dir   string
	mu    sync.Mutex
	cache map[string]*Session
}

// NewStore 创建以 dir 为数据目录的存储。
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir, cache: map[string]*Session{}}, nil
}

func (st *Store) path(id string) string {
	return filepath.Join(st.dir, id+".json")
}

// Get 读取会话(不存在时 ok=false), 不创建。
func (st *Store) Get(id string) (sess *Session, ok bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.loadLocked(id)
}

func (st *Store) loadLocked(id string) (*Session, bool, error) {
	if s, hit := st.cache[id]; hit {
		return s, true, nil
	}
	data, err := os.ReadFile(st.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, fmt.Errorf("审计 %s 的冻结记录损坏: %w", id, err)
	}
	if s.Buffered == nil {
		s.Buffered = map[uint32]*Frag{}
	}
	if s.Seen == nil {
		s.Seen = map[uint32]SeenRec{}
	}
	if s.SeenFwd == nil {
		s.SeenFwd = map[string]int{}
	}
	st.cache[id] = &s
	return &s, true, nil
}

func (st *Store) saveLocked(s *Session) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path(s.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, st.path(s.ID))
}

// Submit 以捕获顺序提交一批报文:
//   - 与已冻结位置重叠的包必须字节完全相同, 原样返回冻结裁决(幂等重放);
//   - 重叠部分字节不同则返回 Conflict, 不应用任何新包;
//   - 其余包按顺序裁决并冻结。
//
// 每批至多 MaxPackets 个包, 会话总量也不超过 MaxPackets。
func (st *Store) Submit(id string, raws [][]byte) (*View, *Conflict, error) {
	if len(raws) > MaxPackets {
		return nil, nil, fmt.Errorf("一次至多提交 %d 个包, 实收 %d", MaxPackets, len(raws))
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok, err := st.loadLocked(id)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		s = NewSession(id)
		st.cache[id] = s
	}
	frozen := len(s.Verdicts)
	overlap := len(raws)
	if frozen < overlap {
		overlap = frozen
	}
	for i := 0; i < overlap; i++ {
		if !bytes.Equal(s.Raw[i], raws[i]) {
			return nil, &Conflict{
				Index:               i,
				FrozenSHA256:        shaOf(s.Raw[i]),
				FrozenFirstBytesHex: firstHex(s.Raw[i], 16),
				GotSHA256:           shaOf(raws[i]),
			}, nil
		}
	}
	if frozen+len(raws)-overlap > MaxPackets {
		return nil, nil, fmt.Errorf("审计 %s 的包总数将超过 %d", id, MaxPackets)
	}
	for i := overlap; i < len(raws); i++ {
		s.Apply(raws[i])
	}
	if err := st.saveLocked(s); err != nil {
		return nil, nil, err
	}
	return s.View(), nil, nil
}
