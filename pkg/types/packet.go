package types

// Packet 表示处理流水线中传递的数据包
type Packet struct {
    ID        string
    Timestamp int64
    RawData   []byte
    Protocol  string
    Features  map[string]interface{}
    Error     error
}

// Stage 表示处理阶段的状态
type Stage int

const (
    StageProtocolParsing Stage = iota + 1
    StageBasicFeatureExtraction
    StageProtocolFeatureExtraction
    StageRuleDetection
    StateAnomalyDetection
) 